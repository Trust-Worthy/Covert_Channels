import math
import time
import numpy as np
import torch
import pdb
import sys
import torch.nn as nn
import torch.nn.functional as F
import torch.utils.data as data_utils
from torch.utils.data import Dataset, DataLoader
from predictions import *
#import seaborn as sns
#import pandas as pd
import matplotlib.pyplot as plt
#import matplotlib.image.AxesImage
from datetime import datetime
import os.path

def gen_net_mlp_main(X_train, Y_labels,X_test_file_list, Y_test_file_list, features, iterations, hidden_nodes, classes, alpha, batch_size):#, train_loader):
    #print("In net model mlp main.")

    batch_size=batch_size
    D_in=features
    H2=hidden_nodes
    H1=2*hidden_nodes
    print("Model basic parameters:",features, iterations, hidden_nodes, classes, alpha, batch_size)
    iteration_ctr=0
    D_out=classes  #Y_labels.shape[0]
    epochs=iterations
    alpha=alpha
    max_iter=20
    train=data_utils.TensorDataset(X_train, Y_labels)
    train_loader=data_utils.DataLoader(train, batch_size=batch_size,shuffle=False)

    #The following lines define the model. Configurable.
    net_model=torch.nn.Sequential(
    torch.nn.Linear(D_in, H1),
    torch.nn.ReLU(),
    torch.nn.Linear(H1,H1),
    torch.nn.ReLU(),
##    #added
    torch.nn.Linear(H1,H2),
    torch.nn.ReLU(),
    torch.nn.Linear(H2, D_out),
    torch.nn.Softmax(dim=1)
    )
    
    #print("device count",torch.cuda.device_count())
    dtype=torch.float

    use_cuda=torch.cuda.is_available()
    device=torch.device("cuda:0" if use_cuda else "cpu")
    print("Device:",device)
    x=X_train
    print("Shape of x",x.size())
    y=Y_labels
    print("Shape of y",y.size())
    print()
    #print(datetime.now(),"Loss for epoch:", epoch, loss.item())
    #        break
    loss_array=torch.zeros(epochs,1)
    tick=datetime.now()

    loss_fn=torch.nn.MSELoss(reduction='sum')

    optimizer=optimizer_pick(1,net_model,alpha)
        
    epoch_ctr=0
    for epoch in range(epochs):
        batch_ctr=0
        for i, data in enumerate(train_loader,1):
            inputs, targets = data
            inputs=inputs.float()            

            y_pred=net_model((inputs).float()) #Each iteration updates the model prediction for the packets
           
            loss=loss_fn(y_pred, targets.float())   #Calculate the difference between the prediction and ground truth.
            time=str(datetime.now())  
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            batch_ctr=batch_ctr+1
                               
        loss_array[epoch]=loss.item() #Keeps track of loss over time.

        if epoch%10==0:
            print(loss.item())
        
        epoch_ctr=epoch_ctr+1
                
        if loss.item() < 1e-12:
            print(datetime.now(),"Loss for epoch:", epoch, loss.item())
            break
    
    torch.save(net_model.state_dict(),'params.pt')
    tock=datetime.now()
    delta_time=tock-tick
    print()
    print("Done with general training. Total time:",delta_time)

    #print(tick)
    #print(tock)
    print()
    print("Starting to test datasets.")
    plt.figure()
    plt.ion()
    plt.plot(loss_array)
    plt.ylabel('cost')
    plt.xlabel('iterations (per hundreds)')
    plt.title("General Loss")
    plt.savefig('gen.png')
    plt.show()
    tcp_packet_list_list=[]
    #print(len(X_test_file_list))
    #runs=len(X_test_file_list)
    for l in range(len(X_test_file_list)):
        X_test=X_test_file_list[l]
        Y_test=Y_test_file_list[l]
        print(X_test)
        print(Y_test)
        X_test=np.load(X_test)
        X_test=np.transpose(X_test)
        X_test=torch.from_numpy(X_test).float()
        
        Y_test=np.load(Y_test)
        Y_test=np.transpose(Y_test)
        Y_test=torch.from_numpy(Y_test)
        Y_test_labels=torch.zeros(X_test.shape[0],classes)

        y_test_pred=net_model(X_test)
        
        predicted=torch.zeros(X_test.shape[0])
        
        for i in range(X_test.shape[0]):
            place=torch.argmax(y_test_pred[i])
            #if i < 100:
            #    print(place)
            predicted[i]=place
        predicted_numpy=predicted.numpy()

        packet_choice(predicted_numpy)
        accuracy(predicted_numpy, Y_test)

        #tcp_packet_list_list.append(tcp_packet_list)

    #return tcp_packet_list_list

def optimizer_pick(choice,net_model,alpha):
    #optimizer=torch.optim.Adadelta(net_model.parameters(),lr=1.0,rho=0.9,eps=1e-06,weight_decay=0)
    #optimizer=torch.optim.Adadelta(net_model.parameters(),lr=1.0,rho=0.9,eps=1e-06,weight_decay=1e-2)
    #optimizer=torch.optim.Adagrad(net_model.parameters(),lr=alpha,lr_decay=0,weight_decay=0,initial_accumulator_value=0)
    #optimizer=torch.optim.Adagrad(net_model.parameters(),lr=alpha,lr_decay=0,weight_decay=1e-2,initial_accumulator_value=0)
    optimizer=torch.optim.Adam(net_model.parameters(),lr=alpha) #Same as next Adam
    #optimizer=torch.optim.Adam(net_model.parameters(),lr=alpha,betas=(0.9,0.999),eps=1e-08,weight_decay=0,amsgrad=False)
    #optimizer=torch.optim.Adam(net_model.parameters(),lr=alpha,betas=(0.9,0.999),eps=1e-08,weight_decay=1e-2,amsgrad=False)
    #optimizer=torch.optim.Adam(net_model.parameters(),lr=alpha,betas=(0.9,0.999),eps=1e-08,weight_decay=1e-2,amsgrad=True)
    #optimizer=torch.optim.SparseAdam(net_model.parameters(),lr=alpha,betas=(0.9,0.999),eps=1e-08)  #Gradient too dense
    #optimizer=torch.optim.Adamax(net_model.parameters(),lr=alpha,betas=(0.9,0.999),eps=1e-08)
    #optimizer=torch.optim.Adamax(net_model.parameters(),lr=alpha,betas=(0.9,0.999),eps=1e-08,weight_decay=1e-2)
    #optimizer=torch.optim.ASGD(net_model.parameters(),lr=alpha, lambd=.0001, alpha=.75,t0=1000000.0,weight_decay=0)
    #optimizer=torch.optim.ASGD(net_model.parameters(),lr=alpha, lambd=.0001, alpha=.75,t0=1000000.0,weight_decay=1e-2)
    #optimizer=torch.optim.LBFGS(net_model.parameters(),lr=alpha, max_iter=20,max_eval=None,tolerance_grad=1e-05,tolerance_change=1e-09,history_size=100,line_search_fn=None)
    #max_eval=max_iter*1.25, history_size=150
    #optimizer=torch.optim.RMSprop(net_model.parameters(),lr=alpha,alpha=0.99,eps=1e-08,weight_decay=0, momentum=0,centered=False)
    #optimizer=torch.optim.RMSprop(net_model.parameters(),lr=alpha,alpha=0.99,eps=1e-08,weight_decay=1e-2, momentum=0,centered=False)
    #optimizer=torch.optim.RMSprop(net_model.parameters(),lr=alpha,alpha=0.99,eps=1e-08,weight_decay=1e-2, momentum=.9,centered=False)
    #optimizer=torch.optim.RMSprop(net_model.parameters(),lr=alpha,alpha=0.99,eps=1e-08,weight_decay=1e-2, momentum=.9,centered=True)
    #optimizer=torch.optim.Rprop(net_model.parameters(),lr=alpha,etas=(0.5,1.2),step_sizes=(1e-06,50))
    #optimizer=torch.optim.SGD(net_model.parameters(),lr=alpha,momentum=0.9,dampening=0,weight_decay=0,nesterov=True)
    #optimizer=torch.optim.SGD(net_model.parameters(),lr=alpha,momentum=0.9,dampening=0,weight_decay=1e-2,nesterov=False)
    #optimizer=torch.optim.SGD(net_model.parameters(),lr=alpha,momentum=0.9,dampening=0,weight_decay=1e-2,nesterov=True)
    print("Optimizer:",optimizer)
    print()
    return optimizer

