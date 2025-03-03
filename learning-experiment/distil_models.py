import os
from dotenv import load_dotenv

from data import *
from models import *
from history_callback import *

import tensorflow as tf
from keras.models import load_model
from tqdm import tqdm

tf.get_logger().setLevel('ERROR')

# parameters
TEMPERATURE = 3.0
ALPHA = 0.5
BATCH_SIZE = 32
EPOCHS = 5
NUM_MODELS = 20
WINDOW_SIZE = 15
LABEL_AHEAD = 1
ACTIVITIES = ['sleep', 'eat', 'personal', 'work', 'leisure', 'other']
# Paths
DATA_PATH = os.environ.get("DATA_PATH")
BASE_DATA_PATH = os.path.join(DATA_PATH, "openshs/twenty-one-clients/")
TEACHER_MODEL_PATH_TEMPLATE = "models/0_students/model_{}"
DISTILLED_MODEL_PATH_TEMPLATE = "models/distilled/temp_{}/model_{}"

# distillation loss function
def distillation_loss(y_true, y_pred, teacher_preds, temperature=TEMPERATURE, alpha=ALPHA):
    y_pred_soft = tf.nn.softmax(y_pred / temperature)
    teacher_preds_soft = tf.nn.softmax(teacher_preds / temperature)
    kd_loss = tf.keras.losses.KLDivergence()(teacher_preds_soft, y_pred_soft) * (temperature ** 2)
    ce_loss = tf.keras.losses.categorical_crossentropy(y_true, y_pred)
    return alpha * kd_loss + (1 - alpha) * ce_loss

# Distillation
def distill_models():
    # each teacher model and perform distillation
    for i in range(1, NUM_MODELS + 1):
        print(f"\nDistilling model {i}/{NUM_MODELS}...")

        # load teacher model
        teacher_model = load_model(TEACHER_MODEL_PATH_TEMPLATE.format(i))

        # load data for the specific client
        f_name = os.path.join(BASE_DATA_PATH, f"gen_adl_{i}.csv")
        d = DATASET()
        d.load_data(f_name, ACTIVITIES)
        train_data, test_data = d.split_data(test_percentage=0.3)
        trainX, trainY, activity_mapping = d.form_data(train_data, WINDOW_SIZE, LABEL_AHEAD)

        # student model
        input_shape = (trainX.shape[1], trainX.shape[2])
        num_classes = trainY.shape[1]
        student_model = build_lstm_student(input_shape[0], input_shape[1], num_classes)
        optimizer = tf.keras.optimizers.Adam()

        # train the student model
        for epoch in range(EPOCHS):
            print(f"Epoch {epoch + 1}/{EPOCHS}")
            for batch_start in tqdm(range(0, len(trainX), BATCH_SIZE), desc="Processing batches"):
                batch_X = trainX[batch_start:batch_start + BATCH_SIZE]
                batch_Y = trainY[batch_start:batch_start + BATCH_SIZE]
                
                # get teacher's predictions for the batch
                teacher_preds = teacher_model.predict(batch_X, verbose=0)

                # train step for the student model
                with tf.GradientTape() as tape:
                    student_preds = student_model(batch_X, training=True)
                    loss = distillation_loss(batch_Y, student_preds, teacher_preds)
                
                # apply gradients
                gradients = tape.gradient(loss, student_model.trainable_variables)
                optimizer.apply_gradients(zip(gradients, student_model.trainable_variables))
            
            print(f"Loss after epoch {epoch + 1}: {loss.numpy()}")

        # save distilled student model
        distilled_model_path = DISTILLED_MODEL_PATH_TEMPLATE.format(int(TEMPERATURE), i)
        os.makedirs(distilled_model_path, exist_ok=True)
        student_model.save(distilled_model_path)
        print(f"Model {i} distilled and saved at {distilled_model_path}\n")

distill_models()
