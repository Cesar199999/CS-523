import numpy as np
import os
import dpkt
import pandas as pd
import re
import sys

from ipaddress import ip_address
from typing import TypedDict, List
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score

class Trace(TypedDict):
    filename: str
    trace_grid_id: int
    trace_len: int

def classify(train_features, train_labels, test_features, test_labels):

    """Function to perform classification, using a 
    Random Forest. 

    Reference: https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html
    
    Args:
        train_features (numpy array): list of features used to train the classifier
        train_labels (numpy array): list of labels used to train the classifier
        test_features (numpy array): list of features used to test the classifier
        test_labels (numpy array): list of labels (ground truth) of the test dataset

    Returns:
        predictions: list of labels predicted by the classifier for test_features

    Note: You are free to make changes the parameters of the RandomForestClassifier().
    """

    # Initialize a random forest classifier. Change parameters if desired.
    clf = RandomForestClassifier(n_jobs=-1, n_estimators=200)
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)

    predicted_probs = clf.predict_proba(test_features)
    
    return predictions, predicted_probs

def perf_evaluation(true_labels, predicted_labels, predicted_probs):
    
    perf_metrics = {}
    accuracy = accuracy_score(true_labels, predicted_labels)
    precision = precision_score(true_labels, predicted_labels, average='weighted')
    recall = recall_score(true_labels, predicted_labels, average='weighted')
    f1 = f1_score(true_labels, predicted_labels, average='weighted')

    perf_metrics['accuracy'] = accuracy
    perf_metrics['precision'] = precision
    perf_metrics['recall'] = recall
    perf_metrics['f1-score'] = f1

    return perf_metrics

def aggregate_performance(performance_metrics_list):
    """
    Function to aggregate performance metrics across all folds.
    Args:
        performance_metrics_list (list): list of performance metrics dictionaries for each fold
    Returns:
        aggregated_metrics (dict): dictionary of aggregated performance metrics
    """
    aggregated_metrics = {}

    accuracies = []
    precisions = []
    recalls = []
    f1_scores = []
    auc_rocs = []

    for metrics in performance_metrics_list:
        accuracies.append(metrics['accuracy'])
        precisions.append(metrics['precision'])
        recalls.append(metrics['recall'])
        f1_scores.append(metrics['f1-score'])

    aggregated_metrics['accuracy_mean'] = np.mean(accuracies)
    aggregated_metrics['precision_mean'] = np.mean(precisions)
    aggregated_metrics['recall_mean'] = np.mean(recalls)
    aggregated_metrics['f1_score_mean'] = np.mean(f1_scores)

    aggregated_metrics['accuracy_std'] = np.std(accuracies)
    aggregated_metrics['precision_std'] = np.std(precisions)
    aggregated_metrics['recall_std'] = np.std(recalls)
    aggregated_metrics['f1_score_std'] = np.std(f1_scores)

    return aggregated_metrics

def perform_crossval(features, labels, folds=10):

    """Function to perform cross-validation.
    Args:
        features (list): list of features
        labels (list): list of labels
        folds (int): number of fold for cross-validation (default=10)
    Returns:
        You can modify this as you like.
    
    This function splits the data into training and test sets. It feeds
    the sets into the classify() function for each fold. 

    You need to use the data returned by classify() over all folds 
    to evaluate the performance.         
    """

    kf = StratifiedKFold(n_splits=folds)
    labels = np.array(labels)
    features = np.array(features)
    fold_perf = []
    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions, predicted_probs = classify(X_train, y_train, X_test, y_test)

        fold_perf.append(perf_evaluation(y_test, predictions, predicted_probs))
    
    global_perf = aggregate_performance(fold_perf)

    print("accuracy: "+str(global_perf['accuracy_mean']))
    print("precision: "+str(global_perf['precision_mean']))
    print("recall: "+str(global_perf['recall_mean']))
    print("f1_score: "+str(global_perf['f1_score_mean']))

def load_data():

    """Function to load data that will be used for classification.

    Args:
        You can provide the args you want.
    Returns:
        features (list): the list of features you extract from every trace
        labels (list): the list of identifiers for each trace
    
    An example: Assume you have traces (trace1...traceN) for cells with IDs in the
    range 1-N.  
    
    You extract a list of features from each trace:
    features_trace1 = [f11, f12, ...]
    .
    .
    features_traceN = [fN1, fN2, ...]

    Your inputs to the classifier will be:

    features = [features_trace1, ..., features_traceN]
    labels = [1, ..., N]

    Note: You will have to decide what features/labels you want to use and implement 
    feature extraction on your own.
    """

    # preprocess traces
    traces_name = os.listdir("data_collection/")
    traces = pre_process_pcap_file(traces_name)

    # now we want to remove outliers using interquartile methods
    dataframe = pd.DataFrame(data=traces)
    dataframe = dataframe.set_index('trace_grid_id')
    dataframe = dataframe.sort_index()

    filtered_traces = remove_outliers(dataframe)
    traces_name_filtered = [filename for filename in traces_name if filename in filtered_traces.filename.values.tolist()]

    features = []
    labels = []
    
    features = extract_features(traces_name_filtered)
    labels = extract_labels(traces_name_filtered)

    return features, labels    

def extract_labels(traces):
    labels = []
    for trace in traces:
        labels.append([int(s) for s in re.split('[_.]', trace) if s.isdigit()][0])
    return labels

def first_packet_is_from_client(trace):
    with open("data_collection/"+trace,'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        packet_count = 0

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            if ip.p == dpkt.ip.IP_PROTO_TCP:
                return ip_address(ip.src).is_private

def pre_process_pcap_file(directory) -> List[Trace]:
    traces = []
    for filename in directory:
        packet_count = 0
        packet_count = count_packet(filename)

        #if first_packet_is_from_client(filename):
        traces.append({'filename': filename, 'trace_grid_id' : [int(s) for s in re.split('[_.]', filename) if s.isdigit()][0], 'trace_len': packet_count})

    return traces

def remove_outliers(dataframe, tresholds = 1.5):
    q1 = dataframe['trace_len'].quantile(0.25)
    q3 = dataframe['trace_len'].quantile(0.75)

    iqr = q3-q1

    lower_limit = q1 - (tresholds*iqr)
    upper_limit = q3 + (tresholds*iqr)

    filtered_dataframe = dataframe[(dataframe['trace_len'] >= lower_limit) & (dataframe['trace_len']<=upper_limit) & (dataframe['trace_len'] != 0)]

    return filtered_dataframe

def count_packet(trace) -> int:
    with open("data_collection/"+trace,'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        packet_count = 0

        for timestamp, buf in pcap:
            if len(buf) == 0:
                return 0
            ip = dpkt.ethernet.Ethernet(buf).data
            if not ip_address(ip.src).is_private:
                packet_count+=1
 
    return packet_count

def measure_time_exchange(trace) -> float:
    with open("data_collection/"+trace,'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        
        start_time = float('inf')
        end_time = float('-inf')
        for timestamp, buff in pcap:
            if start_time == float('inf'):
                start_time = timestamp
            else:
                end_time = timestamp

    return end_time-start_time

def count_rounds(trace):
    with open("data_collection/"+trace,'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        rounds = 0
        rounds_size = []
        rounds_timestamps = []
        current_round_size = 0
        last_seq = None

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            if current_round_size == 0:
                
                rounds_timestamps.append(timestamp)
        
            if last_seq is None:
                last_seq = tcp.seq
            elif tcp.seq > last_seq:
                rounds += 1
                rounds_size.append(current_round_size)
                current_round_size = 0

            last_seq = tcp.seq
            current_round_size += len(buf)
    
    return rounds, rounds_size, rounds_timestamps

def compute_total_size(trace):
    with open("data_collection/"+trace,'rb') as pcap_file:

        pcap = dpkt.pcap.Reader(pcap_file)
        total_size = 0

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not ip_address(ip.src).is_private:
                total_size += ip.len
    
    return total_size

def extract_features(filenames) -> List[List]:
    features = []
    for trace in filenames:

        # extract number of packet in the trace
        nb_packet = count_packet(trace)

        # extract exchange duration
        exchange_duration = measure_time_exchange(trace)

        # count the number of round
        nb_rounds, size_per_rounds, timestamps = count_rounds(trace)

        # communication size in Byte of server packet
        size = compute_total_size(trace)

        trace_feature = [nb_packet, exchange_duration, nb_rounds, size]

        features.append(trace_feature)
  
    return features
    
def main():

    """Please complete this skeleton to implement cell fingerprinting.
    This skeleton provides the code to perform classification 
    using a Random Forest classifier. You are free to modify the 
    provided functions as you wish.

    Read about random forests: https://towardsdatascience.com/understanding-random-forest-58381e0602d2
    """

    features, labels = load_data()
    perform_crossval(features, labels, folds=10)
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)