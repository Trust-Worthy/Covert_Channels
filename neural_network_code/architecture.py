#This file calls the preprocessor and then the model and predictor.

import torch
import torch.multiprocessing
import torch.nn as nn
import torch.nn.functional as F
import torch.utils.data as data_utils
from torch.utils.data import Dataset, DataLoader
import numpy as np
import time

#Files I wrote
from wireshark_parser import *
from gen_net_model_mlp import *
from predictions import *

def __main__():
    tickety=datetime.now()

    #Directories for all the dataset files
    dataset_dir="c:\\python_code\\datasets\\general\\"
    cleaned_dataset_dir='c:\\python_code\\datasets_cleaned\\'
    numpy_dir='c:\\python_code\\datasets_numpy\\'
    conv_dir='c:\\python_code\\datasets_conv\\' 

    #The following lines describe the basic configurable parameters of the system. 
    features=128     #Number of hex characters from each packet.
    iterations=401    #Number of times through the model - at 401 the best general accuracy is above 99.9%
    alpha=1e-5       #How fast/aggressively does the model learn?
    hidden_nodes=42  #Size of the middle layers
    classes=14       #How many packet types?   
    batch_size=128   #Packets to process at one time in the model
    num_data_files=3 #How many capture files - the first one is always the training file.
       
    X_test_file_list,Y_test_file_list,dataset_file_list,cleaned_file_list=[],[],[],[]

    print()
    print("Let's create the necessary file lists.")
    print()

    for i in range(0,num_data_files):   #Loop to build the necessary file lists.
        filename=dataset_dir+"dataset"+str(i)+".txt"
        dataset_file_list.append(filename)
        cleaned_file=cleaned_dataset_dir+"w_dataset"+str(i)+".txt"
        cleaned_file_list.append(cleaned_file)
        
        X_file=numpy_dir+"w_dataset"+str(i)+"_features.npy"
        X_test_file_list.append(X_file)
        
        Y_file=numpy_dir+"w_dataset"+str(i)+"_labels.npy"
        Y_test_file_list.append(Y_file)
        print("Adding: ")
        print(filename)
        print(cleaned_file)
        print(X_file)
        print(Y_file,"\n")

    print()
    print("Time to call the preprocessor to clean the data and populate the files.")
    print()

    preprocessor_main(features,classes,dataset_file_list,cleaned_file_list,X_test_file_list,Y_test_file_list)

    for i in range(0,1):  #This loop reruns all of the training and tests when desired, normally just runs once

        X_train_file=numpy_dir+"X_trainer.npy"   #Train file for gen packet NN
        Y_train_file=numpy_dir+"Y_labels.npy"     #Labels for gen packet NN
        numpy_X_train=np.load(X_train_file)
        numpy_X_train=np.transpose(numpy_X_train)
        X_train=torch.from_numpy(numpy_X_train)
        numpy_Y_train=np.load(Y_train_file)
        Y_labels=torch.from_numpy(numpy_Y_train)
        print("Loading the previously saved training dataset and the labels file and arranging the matrix shapes.")
        print("Training and label array sizes.")
        print("X_train shape",X_train.shape[0],X_train.shape[1])
        print("Y_labels shape",Y_labels.shape[0],Y_labels.shape[1])

        print()
        print("####################################")
        print()
        print("Calling the general MLP model.")
        print()
        print("####################################")
        print()

        gen_net_mlp_main(X_train, Y_labels,X_test_file_list, Y_test_file_list, features, iterations, hidden_nodes, classes, alpha, batch_size)#, train_loader)
        i=i+1

__main__()
    
    
