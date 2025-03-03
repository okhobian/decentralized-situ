import os
import time
import json
import random
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from dotenv import load_dotenv
from collections import defaultdict
from tqdm import tqdm

from utils import *
from data import *
from models import *
from history_callback import *
# from situ_similarity import *

from keras.models import clone_model, load_model
from sklearn.metrics import confusion_matrix
from sklearn.metrics import f1_score
from sklearn.metrics.pairwise import cosine_similarity
from scipy.cluster.hierarchy import dendrogram, linkage, to_tree
from scipy.spatial.distance import cosine

ACTIVITIES = ['sleep', 'eat', 'personal', 'work', 'leisure', 'other']
WINDOW_SIZE = 15
LABEL_AHEAD = 1

NUM_MODELS = 21
NUM_SHUFFLED_ITERATIONS = 1
NUM_CHUNKS = 30 # [5, 10, 15, 20, 25, 30, 40, 50]
NUM_NEIGHBORS = 20 # max 20 given 21 datasets in total
NUM_STUDENT_NEIGHBORS = 0 # [2, 6, 10, 14, 18] # 10%, 30%, 50%, 70%, 90%
TEMPERATURE = 3

LINKAGE = 'single'  # single, complete, centroid (average, median), ward
RAND_DRAW = False
RAND_P = 0.5

load_dotenv()
data_path = os.environ.get("DATA_PATH")
data_path = os.path.join(data_path, "openshs/twenty-one-clients/")
out_path   = f"output/T_{WINDOW_SIZE}/{NUM_SHUFFLED_ITERATIONS}_iter_{NUM_CHUNKS}_chunk/"
model_path = f"models/{NUM_STUDENT_NEIGHBORS}_students/"
distil_model_path = f"models/distilled/temp_{TEMPERATURE}/"

if not os.path.exists(out_path):
    os.makedirs(out_path)

def predict_chunk(chunk:tuple, models:list):
    '''
    chunk[0]: (len(chunk), 15,29)   trainX
    chunk[1]: (len(chunk), 6)       trainY
    '''
    
    # get batch predictions of current chunk by all models
    pred_Ys = np.array([np.argmax(model.predict(chunk[0], verbose=0), axis=1) for model in models]).T       
    
    # flatten the time series data to 15*29
    num_sample = chunk[0].shape[0]
    num_sequence = chunk[0].shape[1]
    num_sensor = chunk[0].shape[2]
    X = chunk[0].reshape(num_sample, num_sequence*num_sensor)

    # convert one-hot encoded labels (true label) to integer format
    Y = np.argmax(chunk[1], axis=1).reshape(chunk[1].shape[0], )
    
    return X, Y, pred_Ys

def get_x_cluster(chunks, chunk_cnt):
    num_draw = int(chunks[chunk_cnt][0].shape[0]*RAND_P) # RAND_P % of chunk_size
    random_indices = np.random.choice(validX_0.shape[0], size=num_draw, replace=False)  # replace=False ensures unique indices
    rand_X = validX_0[random_indices]
    rand_Y = validY_0[random_indices]
    return rand_X, rand_Y
    newX = np.concatenate((chunks[chunk_cnt][0], rand_X), axis=0)
    newY = np.concatenate((pred_Y, rand_Y), axis=0)

def calculate_sim_matrix(models, rand_X, batch_size=32):
    # initialize an overall similarity matrix of size (num_models, num_models)
    num_models = len(models)
    overall_similarity_matrix = np.zeros((num_models, num_models))
    num_samples = len(rand_X)
    
    # process rand_X in batches
    for i in tqdm(range(0, num_samples, batch_size), desc="Processing batches"):
        batch = rand_X[i:i + batch_size]
        
        # get softmax outputs for all models in the batch
        batch_softmax_outputs = []
        for model in models:
            batch_predictions = model.predict(batch, verbose=0)  # Predict on the entire batch
            batch_softmax_outputs.append(batch_predictions)
        
        # calculate cosine similarity for each pair of models on the batch
        for m1 in range(num_models):
            for m2 in range(m1, num_models):  # Only calculate upper triangular part
                # Get pairwise similarities for current batch and accumulate
                similarities = cosine_similarity(batch_softmax_outputs[m1], batch_softmax_outputs[m2])
                avg_similarity = np.mean(similarities)  # Average similarity across batch
                overall_similarity_matrix[m1, m2] += avg_similarity
                if m1 != m2:
                    overall_similarity_matrix[m2, m1] += avg_similarity  # Symmetric update
    
    # normalize by the number of batches
    overall_similarity_matrix /= (num_samples // batch_size)
    
    return overall_similarity_matrix


def calculate_cluster(sim_matrix, method):
    
    # get linkage matrix Z from hierarchical clustering
    Z = linkage(sim_matrix, method) # average, single, complete, centroid, median, ward

    # convert linkage matrix to tree structure
    node_dict = {}
    rootnode, nodelist = to_tree(Z, rd=True)
    add_parent_info(rootnode)   # add parent pointer to the original tree struct
    for node in nodelist:       # actual (leaf) nodes to dict, ref by their id (model_i)
        if node.is_leaf():
            node_dict[node.id] = node
    
    return Z, node_dict
    
def calculate_weights(node_dict):
    distances = [None] * len(node_dict) # distances from current model's prespective to all other nodes
    curr_node = node_dict[0]

    ## get distances from curr_node to all other nodes
    for key, node in node_dict.items():
        if key == 0:    # distance from curr_node to itself is 0
            distances[key] = 0
        else:           # calculate distance from node0 to current node
            distances[key] = find_LCA_and_distance(curr_node, node)
    distances = np.array(distances)
    
    distances[distances == 0] = 1
    inverse_weights = 1 / distances
    normalized_weights = inverse_weights / np.sum(inverse_weights)  # Normalize the weights so that they sum to 1
    return normalized_weights, distances

def weighted_voting(Y, pred_Ys, weights):
    # convert to one-hot and Apply weights to one-hot encoded predictions
    one_hot_predictions = np.eye(len(ACTIVITIES))[pred_Ys]
    weighted_predictions = one_hot_predictions * weights.reshape(1, NUM_MODELS, 1)

    # sum over one-hots to get scores for each situ
    scores = weighted_predictions.sum(axis=1)           # sum all scores
    voted_situs = scores.argmax(axis=1)                 # situ-int with the hightest score
    
    # discrepancy between voted Situ and groundtruth (% diff)
    dissimilarities = np.sum(voted_situs != Y) / len(Y) * 100   # hamming_distance
    
    # convert back to one-hot for training
    voted_situs = np.eye(len(ACTIVITIES))[voted_situs]  
    
    return voted_situs, dissimilarities

def shuffle_chunks(chunks_dict):
    for model_id, chunks in chunks_dict.items():
        shuffled_chunks = chunks.copy()
        random.shuffle(shuffled_chunks)
        chunks_dict[model_id] = shuffled_chunks
    return

##############################################################################
def cosine_similarity_between_matrices(matrix1, matrix2):
    assert matrix1.shape == matrix2.shape, "Matrices must have the same shape."
    
    # cosine similarity between corresponding rows
    similarities = [cosine_similarity(matrix1[i].reshape(1, -1), matrix2[i].reshape(1, -1))[0, 0] 
                    for i in range(matrix1.shape[0])]
    
    # average similarity across all rows
    average_similarity = np.mean(similarities)
    return average_similarity


## Load all models
start_time = time.time()
models = []
for i in range(NUM_MODELS):
    if i <= NUM_STUDENT_NEIGHBORS:
        model_dir = model_path + f"{NUM_CHUNKS}_chunks/model_{i}"   # student models
        models.append(load_model(model_dir))
    else:
        # model_dir = model_path + f"model_{i}"                       # teacher models
        model_dir = distil_model_path + f"model_{i}"  
        models.append(load_model(model_dir))
print(f"!! MODELS LOADED: {time.time() - start_time:.4f} seconds")

## Load chunks - under gen_adl_n - where n = NUM_STUDENT_NEIGHBORS+1
start_time = time.time()
activity_mapping = None
chunks_dict = {}
for i in range(NUM_STUDENT_NEIGHBORS+1):
    curr_model_chunks = []
    for j in range(NUM_CHUNKS):
        chunk_f_name = data_path + f"chunks/gen_adl_{i}/{NUM_CHUNKS}_chunks/chunk_{j}.csv"
        d = DATASET()
        d.load_data(chunk_f_name, ACTIVITIES)
        train_data, _ = d.split_data(test_percentage=0)
        trainX, trainY, activity_mapping  = d.form_data(train_data, WINDOW_SIZE, LABEL_AHEAD)
        curr_model_chunks.append((trainX, trainY))
    chunks_dict[f"model_{i}"] = curr_model_chunks
print(f"!! CHUNKS LOADED: {time.time() - start_time:.4f} seconds")

# Load evaluation set (gen_adl_0)
###############################
start_time = time.time()
f_name = data_path + "gen_adl_0.csv"
d = DATASET()
d.load_data(f_name, ACTIVITIES)
train_data, test_data = d.split_data(test_percentage=0.95)
trainX_0, trainY_0, activity_mapping  = d.form_data(train_data, WINDOW_SIZE, LABEL_AHEAD)
validX_0, validY_0, activity_mapping  = d.form_data(test_data, WINDOW_SIZE, LABEL_AHEAD)
print(f"!! EVALUATION SET LOADED: {time.time() - start_time:.4f} seconds")

###############################

## For each iteration of shuffle
result_training_acc_df = pd.DataFrame()
for iter in range(NUM_SHUFFLED_ITERATIONS):
    # if iter > 1: break
    print(f"*****************************************************************************")
    shuffle_chunks(chunks_dict)
    
    # # Reload model_0 for each shuffle iteration
    # total_accuracies = []
    # models[0] = load_model(model_path + f"{NUM_CHUNKS}_chunks/model_0")
    # eva_loss, eva_accuracy = models[0].evaluate(validX_0, validY_0)
    # total_accuracies.append(eva_accuracy)
    
    total_accuracies = []
    for i in range(NUM_STUDENT_NEIGHBORS+1):
        model_dir = model_path + f"{NUM_CHUNKS}_chunks/model_{i}"   # student models
        models[i] = load_model(model_dir)
        if i==0:
            eva_loss, eva_accuracy = models[i].evaluate(validX_0, validY_0)
            total_accuracies.append(eva_accuracy)
    
    weights = np.zeros(21)
    cum_X = {}
    cum_Y = {}
    cum_pred_Ys = {}
    
    for chunk_cnt in range(NUM_CHUNKS):
        
        items = list(chunks_dict.items())   # Convert dict items to a list and shuffle it
        random.shuffle(items)   # simulate random comminucation orders by delay

        # Iterate over the shuffled list of model_id->chunks (only student models)
        for model_id, chunks in items:
            model_idx = int(model_id.split('_')[1])
            
            print(f"> [iteration {iter}] | [model_{model_idx}] | [chunk_cnt {chunk_cnt}]")
            
            
            ## Get X_cluster
            rand_X, rand_Y = get_x_cluster(chunks, chunk_cnt)

            ## Calculate sim_matrix
            start_time = time.time()        
            avg_sim_all_situ = calculate_sim_matrix(models, rand_X)
            print(avg_sim_all_situ)
            print(f"!! SIMILARITY MATRIX OBTAINED: {time.time() - start_time:.4f} seconds")
            
            # Perform hierarchical clustering
            start_time = time.time()   
            Z, node_dict = calculate_cluster(avg_sim_all_situ, method=LINKAGE)
            # plot_dendrogram(Z)
            print(f"!! CLUSTER OBTAINED: {time.time() - start_time:.4f} seconds")
            
            # Calculate voting weights
            start_time = time.time()
            weights, distances = calculate_weights(node_dict)   
            # weights = np.ones(21)
            # weights = np.zeros(21)
            weights[0] = 0
            print(f"!! WEIGHTS OBTAINED: {time.time() - start_time:.4f} seconds")
            print("!! weights", weights)
            
            # Batch prediction over the chunk by all models
            start_time = time.time()
            X, Y, pred_Ys = predict_chunk(chunks[chunk_cnt], models)
            if chunk_cnt==0: 
                cum_X[model_id] = X
                cum_Y[model_id] = Y
                cum_pred_Ys[model_id] = pred_Ys
            else:
                cum_X[model_id] = np.concatenate((cum_X[model_id], X), axis=0)
                cum_Y[model_id] = np.concatenate((cum_Y[model_id], Y), axis=0)
                cum_pred_Ys[model_id] = np.concatenate((cum_pred_Ys[model_id], pred_Ys), axis=0)
            print(f"!! BATCH PREDICTED: {time.time() - start_time:.4f} seconds")
            
            # Weighted labeling
            start_time = time.time()  
            pred_Y, disim = weighted_voting(Y, pred_Ys, weights)
            print(f"!! VOTED: {time.time() - start_time:.4f} seconds")
            # print("!! disim", disim)
            
            ######################################################################
            
            if not RAND_DRAW:
            
                # Re-train without random draw from self set
                histories = Histories()
                models[model_idx].fit(chunks[chunk_cnt][0], pred_Y, epochs=1, batch_size=30, verbose=0, callbacks=[histories])
                # print ("~~~~~~ ", pred_Y)
                # print ("++++++ ", chunks[chunk_cnt][1])
                # print (cosine_similarity_between_matrices(pred_Y, chunks[chunk_cnt][1]))
                # models[model_idx].fit(chunks[chunk_cnt][0], chunks[chunk_cnt][1], epochs=1, batch_size=30, verbose=0, callbacks=[histories])
                
            else:
            
                # Re-train with random draw from self set
                histories = Histories()
                num_draw = int(chunks[chunk_cnt][0].shape[0]*RAND_P) # RAND_P % of chunk_size
                random_indices = np.random.choice(validX_0.shape[0], size=num_draw, replace=False)  # replace=False ensures unique indices
                rand_X = validX_0[random_indices]
                rand_Y = validY_0[random_indices]
                newX = np.concatenate((chunks[chunk_cnt][0], rand_X), axis=0)
                newY = np.concatenate((pred_Y, rand_Y), axis=0)
                models[model_idx].fit(newX, newY, epochs=1, batch_size=50, verbose=0, callbacks=[histories])
                
                
            if model_idx==0:
                eva_loss, eva_accuracy = models[model_idx].evaluate(validX_0, validY_0)
                total_accuracies.append(eva_accuracy)
                
            ######################################################################
        
    result_training_acc_df[f"iteration_{iter}"] = pd.Series(total_accuracies)

if not RAND_DRAW: result_training_acc_df.to_csv(out_path+f"cos_{LINKAGE}_{NUM_STUDENT_NEIGHBORS}_stu.csv")
else: result_training_acc_df.to_csv(out_path+f"cos_{LINKAGE}_{NUM_STUDENT_NEIGHBORS}_stu_rand{int(RAND_P*100)}p.csv")
# result_training_acc_df.to_csv(out_path+f"true_cumweight.csv")