import os
from dotenv import load_dotenv

from data import *
from models import *
from history_callback import *

load_dotenv()
data_path = os.environ.get("DATA_PATH")
data_path = os.path.join(data_path, "openshs/twenty-one-clients/")
out_path = "output/model_stat/"
model_path = "models/"

ACTIVITIES = ['sleep', 'eat', 'personal', 'work', 'leisure', 'other']
WINDOW_SIZE = 15
LABEL_AHEAD = 1

NUM_CHUNKS = [30] #[5, 10, 15, 20, 25]
NUM_NEIGHBORS = 20 # max 20 given 21 datasets in total
NUM_STUDENT_NEIGHBORS = [0] # [2, 6, 10, 14, 18] # 10%, 30%, 50%, 70%, 90%
##############################################################################

# Load dataset for model_0 && train model_0
##############################################
for num_student in NUM_STUDENT_NEIGHBORS:
    
    for num_chunk in NUM_CHUNKS:
        
        for i in range(0, num_student+1):   # each student model (first num_student_index + model_0)
            print(f"> [{num_student} students] | [{num_chunk} chunks] | [student_model_{i}]")
            f_name = data_path + f"chunks/gen_adl_{i}/{num_chunk}_chunks/chunk_0.csv"
            d = DATASET()
            d.load_data(f_name, ACTIVITIES)
            train_data, test_data = d.split_data(test_percentage=0.3)
            trainX, trainY, activity_mapping  = d.form_data(train_data, WINDOW_SIZE, LABEL_AHEAD)
            testX,  testY,  activity_mapping  = d.form_data(test_data, WINDOW_SIZE, LABEL_AHEAD)
            
            histories = Histories()
            model_i = build_lstm(trainX.shape[1], trainX.shape[2], trainY.shape[1])
            model_i.fit(trainX, trainY, batch_size=30, epochs=1, verbose=0, callbacks=[histories])
            
            result_training_acc_df = pd.DataFrame()
            result_training_time_df = pd.DataFrame()
            result_training_acc_df[f"model_{i}"] = pd.Series(histories.accuracies)
            result_training_time_df[f"model_{i}"] = pd.Series(histories.times)
            
            stat_out_path = out_path+f"{num_student}_students/{num_chunk}_chunks/"
            model_out_path = model_path+f"{num_student}_students/{num_chunk}_chunks/"
            if not os.path.exists(stat_out_path):
                os.makedirs(stat_out_path)
            if not os.path.exists(model_out_path):
                os.makedirs(model_out_path)
            
            result_training_acc_df.to_csv(stat_out_path+f"model_{i}_acc.csv")
            result_training_time_df.to_csv(stat_out_path+f"model_{i}_time.csv")
            model_i.save(model_out_path+f"model_{i}")


# Load dataset for other models && train them
##############################################
for num_student in NUM_STUDENT_NEIGHBORS:
    
    for i in range(num_student+1, NUM_NEIGHBORS+1):
        print(f"> [{num_student} students] | [teacher_model_{i}]")
        
        f_name = data_path + f"gen_adl_{i}.csv"
        d = DATASET()
        d.load_data(f_name, ACTIVITIES)
        train_data, test_data = d.split_data(test_percentage=0.3)
        trainX, trainY, activity_mapping  = d.form_data(train_data, WINDOW_SIZE, LABEL_AHEAD)
        testX,  testY,  activity_mapping  = d.form_data(test_data, WINDOW_SIZE, LABEL_AHEAD)
        
        histories = Histories()
        model_i = build_lstm(trainX.shape[1], trainX.shape[2], trainY.shape[1])
        model_i.fit(trainX, trainY, batch_size=30, epochs=1, verbose=0, callbacks=[histories])
        
        result_training_acc_df = pd.DataFrame()
        result_training_time_df = pd.DataFrame()
        result_training_acc_df[f"model_{i}"] = pd.Series(histories.accuracies)
        result_training_time_df[f"model_{i}"] = pd.Series(histories.times)
        
        stat_out_path = out_path+f"{num_student}_students/"
        model_out_path = model_path+f"{num_student}_students/"
        if not os.path.exists(stat_out_path):
            os.makedirs(stat_out_path)
        if not os.path.exists(model_out_path):
            os.makedirs(model_out_path)
        
        result_training_acc_df.to_csv(stat_out_path+f"model_{i}_acc.csv")
        result_training_time_df.to_csv(stat_out_path+f"model_{i}_time.csv")
        model_i.save(model_out_path+f"model_{i}")