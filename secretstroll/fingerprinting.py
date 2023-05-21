import numpy as np
import os
import re
import dpkt
import sys
import socket

from pandas import DataFrame
from typing import TypedDict, List
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier

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
    clf = RandomForestClassifier()
    # Train the classifier using the training features and labels.
    clf.fit(train_features, train_labels)
    # Use the classifier to make predictions on the test features.
    predictions = clf.predict(test_features)
    
    return predictions

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

    for train_index, test_index in kf.split(features, labels):
        X_train, X_test = features[train_index], features[test_index]
        y_train, y_test = labels[train_index], labels[test_index]
        predictions = classify(X_train, y_train, X_test, y_test)

    ###############################################
    # TODO: Write code to evaluate the performance of your classifier
    ###############################################

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

    ###############################################
    # TODO: Complete this function. 
    ###############################################
    # preprocess packet
    traces_name = os.listdir("/data_collection")
    traces = pre_process_pcap_file(traces_name)

    # know we want to remove outliers using interquartile methods
    dataframe = DataFrame(data=traces)
    filtered_traces = remove_outliers(dataframe)

    # TODO: process filtered data

    features = []
    labels = []

    return features, labels    

def pre_process_pcap_file(directory) -> List[Trace]:
    for filename in directory:
        packet_count = 0

        with open("data_collection/"+filename, 'rb') as pcap_file:
            pcap = dpkt.pcap.Reader(pcap_file)
            for pckt in pcap:  
                packet_count+=1

    return {'filename': filename, 'trace_grid_id' : [int(s) for s in re.findall(r'\b\d+\b', filename)][0], 'trace_len': packet_count}

def remove_outliers(dataframe, tresholds = 1.5):
    q1 = dataframe['trace_len'].quantile(0.25)
    q3 = dataframe['trace_len'].quantile(0.75)

    iqr = q3-q1

    lower_limit = q1 - (tresholds*iqr)
    upper_limit = q2 + (tresholds*iqr)

    filtered_dataframe = dataframe[(dataframe['trace_len'] >= lower_limit) & (dataframe['trace_len']<=upper_limit)]

    return filtered_dataframe

##TODO: not finished
def parse_pcap(filename):

    with open(filename, 'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)

        for timestamp, buf in pcap:
            try:
                eth_hdr = dpkt.ethernet.Ethernet(buf)
                ip_hdr = eth_hdr.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dest)
                if isinstance(ip_hdr.data, dpkt.tcp.TCP):
                    tcp_hdr = ip_hdr.data

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as e:
                print("error during packet extraction")
    
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