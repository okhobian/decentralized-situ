import copy
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from numpy import array
from numpy import argmax
from sklearn.preprocessing import OneHotEncoder
import warnings


class DATASET:
    def __init__(self, df=None, activities=None):
        self.columns = None
        self.activities = activities
        self.df = df
        self.train_data = None
        self.test_data = None
    
    def load_data(self, filename, activities, columns=None):
        if columns:
            self.df = pd.read_csv(filename, delim_whitespace=True, header=None)
            self.columns = columns
            self.activities = activities
            self.df.columns = self.columns
        else:
            self.df = pd.read_csv(filename)
            self.columns = list(self.df.columns)
            self.activities = activities
            self.df.columns = self.columns
            
    def split_data(self, test_percentage=0.4): # default 40%
        train_size  = int(len(self.df) * (1-test_percentage))
        train_data = self.df.iloc[:train_size]
        test_data  = self.df.iloc[train_size:]
        return train_data, test_data
    
    def split_n_chunks(self, n_chunks):
        chunks = np.array_split(self.df, n_chunks)   # Split the DataFrame into n chunks
        return chunks
    
    def form_data(self, df, window_size, label_ahead):
        X = []
        Y = []
        
        _df = df.iloc[0:, :-1].reset_index(drop=True)       # remove header row & timestamp col
        _X = df.iloc[0:, :-2].reset_index(drop=True)        # remove header row & activity+timestamp col
        _Y = pd.get_dummies(df['Activity'], dtype=int)
        _Y = _Y.reindex(columns=self.activities, fill_value=0)
        activity_mapping = {i: col for i, col in enumerate(_Y.columns)}
        
        for i in range(window_size, len(_df) - label_ahead +1):
            X.append(_X.iloc[i - window_size:i, ].values.tolist())
            Y.append(_Y.iloc[i + label_ahead - 1:i + label_ahead].values.reshape(-1,).tolist()) # (18817, 4)
        
        X, Y = np.array(X), np.array(Y)
        return X, Y, activity_mapping
    
    def statics(self):
        fields = {
            "total_sequence": 0,
            "seq_lengths": [],
            "avg_seq_len": 0,
            "max_seq_len": 0,
            "min_seq_len": 0,
            "seq_len_std": 0
        }
        statics = {activity : copy.deepcopy(fields) for activity in self.activities}
        grouped = self.extract_sequences ()
        for _, group in grouped:    # for every activity chunk
            curr_activity = set(group['Activity'])  # remove duplicates from Activity col
            if len(curr_activity) != 1: continue    # invalid chunk
            curr_activity = list(curr_activity)[0]  # get activity string
            statics[curr_activity]["seq_lengths"].append(len(group))

        # results: calculate remaining stats, exclude list of all sequences
        results = {activity : copy.deepcopy(fields) for activity in self.activities}
        for activity in self.activities:
            results[activity]["total_sequence"] = len(statics[activity]["seq_lengths"])
            results[activity]["avg_seq_len"] = int(np.mean(statics[activity]["seq_lengths"]))
            results[activity]["seq_len_std"] = round(float(np.std(statics[activity]["seq_lengths"])),2)
            results[activity]["max_seq_len"] = int(np.max(statics[activity]["seq_lengths"]))
            results[activity]["min_seq_len"] = int(np.min(statics[activity]["seq_lengths"]))
            # np.var(data)
        
        return results
    
    def _plot_stats(self, stats):
        # set width of bar
        barWidth = 0.25
        fig = plt.subplots(figsize =(19, 8))
    
        avgs = []
        maxs = []
        mins = []
        # stds = []
        for activity in self.activities:
            avgs.append(stats[activity]['avg_seq_len'])
            maxs.append(stats[activity]['max_seq_len'])
            mins.append(stats[activity]['min_seq_len'])
            # stds.append(stats[activity]['seq_len_std'])
        
        # Set position of bar on X axis
        br1 = np.arange(len(avgs))
        br2 = [x + barWidth for x in br1]
        br3 = [x + barWidth for x in br2]
        # br4 = [x + barWidth for x in br3]
        
        # Make the plot
        plt.bar(br1, avgs, color ='g', width = barWidth,
                edgecolor ='grey', label ='avgs')
        plt.bar(br2, maxs, color ='y', width = barWidth,
                edgecolor ='grey', label ='maxs')
        plt.bar(br3, mins, color ='b', width = barWidth,
                edgecolor ='grey', label ='mins')
        # plt.bar(br4, stds, color ='r', width = barWidth,
        #         edgecolor ='grey', label ='stds')
        
        # Adding Xticks
        plt.xlabel('Activity', fontweight ='bold', fontsize = 15)
        plt.ylabel('Sequence Length', fontweight ='bold', fontsize = 15)
        plt.xticks([r + barWidth for r in range(len(self.activities))], self.activities)
        
        for i, v in enumerate(avgs):
            plt.text(br1[i]-0.05, v + 0.2, str(v))
        for i, v in enumerate(maxs):
            plt.text(br2[i]-0.05, v + 0.2, str(v))
        for i, v in enumerate(mins):
            plt.text(br3[i]-0.05, v + 0.2, str(v))
        
        plt.legend()
        plt.show()
    
    def _plot_box(self, stats):
        avgs = []
        maxs = []
        mins = []
        stds = []
        for activity in self.activities:
            avgs.append(stats[activity]['avg_seq_len'])
            maxs.append(stats[activity]['max_seq_len'])
            mins.append(stats[activity]['min_seq_len'])
            stds.append(stats[activity]['seq_len_std'])
        
        
        plt.rcParams["figure.figsize"] = [7.50, 3.50]
        plt.rcParams["figure.autolayout"] = True
        df = pd.DataFrame(dict(min=mins, max=maxs, avg=avgs, std=stds))
        df.boxplot()
        
        plt.title("Overall Stats for All Activities")
        plt.ylabel('Sequence Length')
        plt.show()    

    def extract_sequences(self):
        grouped = self.df.groupby( (self.df.Activity != self.df.Activity.shift()).cumsum())    # group by each activity       
        # sequences = []
        # labels = []
        # print(grouped)
        # i = 0
        # for _, group in grouped:    # for every activity chunk
        #     sensor_group = group[group.columns.difference(['Activity', 'timestamp'])].to_numpy()    # only sensor values into numpy
        #     sensor_group = [''.join(row.astype(str)) for row in sensor_group]   # join sensor values to binary str
        #     sensor_group = [[int(sensors, 2)] for sensors in sensor_group]      # into [[x1], [x2], [x3], [x4], [x5], [x6]]
            
        #     group = group.reset_index()
        #     # print(group['Activity'][0])
        #     sequences.append(sensor_group)
        #     labels.append(group['Activity'][0])
            # break
            # i+=1
            # if i > 5:
            #     break
        
        # print(sequences)
        # return np.array(sequences), np.array(labels)
        return grouped
    
        
    def get_df(self):
        return self.df
    
    def get_df_shape(self):
        return self.df.shape
