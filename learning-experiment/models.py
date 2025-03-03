from keras.models import Sequential
from keras.layers import Dense, LSTM, Dropout, GRU, RNN, SimpleRNN
from keras.metrics import CategoricalAccuracy

import tensorflow as tf

def f1_score(y_true, y_pred):
    true_positives = tf.reduce_sum(tf.round(tf.clip_by_value(y_true * y_pred, 0, 1)))
    predicted_positives = tf.reduce_sum(tf.round(tf.clip_by_value(y_pred, 0, 1)))
    possible_positives = tf.reduce_sum(tf.round(tf.clip_by_value(y_true, 0, 1)))

    precision = true_positives / (predicted_positives + tf.keras.backend.epsilon())
    recall = true_positives / (possible_positives + tf.keras.backend.epsilon())

    f1_val = 2 * (precision * recall) / (precision + recall + tf.keras.backend.epsilon())
    return f1_val

import tensorflow as tf
from keras.metrics import Precision, Recall

def macro_f1(y_true, y_pred, num_classes):
    f1_scores = []
    for i in range(num_classes):
        class_true = tf.cast(tf.equal(y_true, i), tf.float32)
        class_pred = tf.cast(tf.equal(tf.argmax(y_pred, axis=-1), i), tf.float32)
        
        precision = Precision()(class_true, class_pred)
        recall = Recall()(class_true, class_pred)
        f1 = 2 * (precision * recall) / (precision + recall + tf.keras.backend.epsilon())
        f1_scores.append(f1)
    
    macro_f1 = tf.reduce_mean(f1_scores)
    return macro_f1

def build_lstm(trainX_window_size, trainX_feature_length, trainY_num_categories):
    model = Sequential()
    model.add(LSTM(64, activation='relu', input_shape=(trainX_window_size, trainX_feature_length), return_sequences=True))
    model.add(LSTM(32, activation='relu', return_sequences=False))
    model.add(Dropout(0.2))
    model.add(Dense(trainY_num_categories, activation='softmax'))
    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    # model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=[macro_f1])
    # model.summary()
    return model

def build_lstm_student(trainX_window_size, trainX_feature_length, trainY_num_categories):
    model = Sequential()
    model.add(LSTM(16, activation='relu', input_shape=(trainX_window_size, trainX_feature_length), return_sequences=True))
    model.add(LSTM(8, activation='relu', return_sequences=False))
    model.add(Dense(trainY_num_categories, activation='softmax'))
    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    # model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=[macro_f1])
    # model.summary()
    return model

def build_rnn(trainX_window_size, trainX_feature_length, trainY_num_categories):
    model = Sequential()
    model.add(SimpleRNN(64, activation='relu', input_shape=(trainX_window_size, trainX_feature_length), return_sequences=False))
    # model.add(RNN(32, activation='relu', return_sequences=False))
    model.add(Dropout(0.2))
    model.add(Dense(trainY_num_categories, activation='softmax'))
    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.summary()
    return model

def build_gru(trainX_window_size, trainX_feature_length, trainY_num_categories):
    model = Sequential()
    model.add(GRU(64, activation='relu', input_shape=(trainX_window_size, trainX_feature_length), return_sequences=True))
    model.add(GRU(32, activation='relu', return_sequences=False))
    model.add(Dropout(0.2))
    model.add(Dense(trainY_num_categories, activation='softmax'))
    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.summary()
    return model