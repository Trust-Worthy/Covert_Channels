#This parser converts the packet to a single X feature vector based on user input.
#This version runs like all of the others: using the first hex character through the
#number of features requested.
#This parser also uses packet_types.py along with the newer datasets 
#for each protocol/type for training.  

from packet_types import *
import numpy as np
from datetime import datetime
import time
import os

def file_type_func(data_file):
    file_type=""
    line_ctr=0
    with open(data_file) as data:
        for i in range(1,2):
            line_ctr=line_ctr+1
            line1=data.readline()
            line2=data.readline()

            if line1[:1]=="+":
                file_type="wireshark"
            if line2[:1]=="\t":
                file_type="tcpdump"
            if line2[:4]=="0000":
                file_type="omnipeek"            
    return file_type

def data_cleaner(X_outfile,source_file, X_cols):
    X_data=open(X_outfile,"w")
    X_line_data=""
    X_line_data_start=""
    line_ctr=0
    adder=0
    pad=""
    with open(source_file) as traffic:
        for line in traffic:
            if line[:1]=="|":  
                X_line_data_start=line
                X_line_data_start=X_line_data_start.replace("|","")
                X_line_data_start=X_line_data_start[4:]
               
                if len(X_line_data_start) >= X_cols: 
                    X_line_data_start=X_line_data_start[:X_cols]
                    X_line_data=X_line_data_start
                    X_data.write(X_line_data+'\n')
                    X_line_data=""
                    X_line_data_start=""
                    line_ctr=line_ctr+1
                else:
                    adder=X_cols-len(X_line_data_start)
                    while adder > -1:
                        #X_line_data_start=X_line_data+"0"
                        pad=pad+"0"
                        adder=adder-1
                    X_line_data=X_line_data_start.strip()+pad

                    pad=""
                    X_data.write(X_line_data+'\n')
                    X_line_data=""
                    X_line_data_start=""
                    line_ctr=line_ctr+1
    X_data.close()

def num_rows(X_outfile):
    X_rows=0
    Y_rows=0
    with open(X_outfile) as data:
        for line in data:
            X_rows=X_rows+1
            Y_rows=Y_rows+1
    return X_rows, Y_rows

def numpy_X_Y(X_rows, X_cols, X_outfile, Y_rows, Y_cols):
    X=np.zeros((X_cols,X_rows))
    Y=np.zeros((Y_rows,Y_cols))
    i=0
    print("numpy_X_Y shapes:",X.shape, Y.shape)

    with open(X_outfile) as traffic:
        for line in traffic:
            for j in range(X_cols):
                #print(i,j,line)
                X[j][i]=int(line[j],16)  #This is a problem with odd nos. due to '/n'
            i=i+1
    return X,Y

def mean_normalize(X, features):
    X_normalized=np.zeros((X.shape[0],X.shape[1]))
    #ctr=0
    for i in range(X.shape[1]):
        X_sum=np.sum(X[:,i])
        X_mean=X_sum/features
        for j in range (X.shape[0]):
            X_normalized[j,i]=X[j,i]-X_mean
        #Y[i]=Y[ctr]/16
        #ctr=ctr+1
    return X_normalized

def fields_and_labels(X_outfile, Y):
    #This function calls other functions depending on L2 Ethertype and L3 PID
    l4_hdr,src_port_num,dst_port_num,l3_pid,src_ip,dst_ip="0","0","0","0","0","0"
    icmp_type_code,igmp_type_code,icmp6_type_code,pim_type,snap,arp_code="0","0","0","0","0","0"
    llc_pid, dsapssap="0","0"
    traffic_class_int=0
    packet,X_line_data="",""
    l3_hdr_len=int
    ctr=0
    zero_ctr=0
    udp_ctr,tcp_ctr,icmp_ctr,arp_ctr,ieee_ctr=0,0,0,0,0

    with open(X_outfile) as traffic:
        for line in traffic:
            traffic_class_int=0
            #traffic_class="0"           
            packet="Other"
            X_field_data=[]
            X_line_data=line
            #print(X_line_data)
            #print(line)
            dst_mac=X_line_data[:12]
            src_mac=X_line_data[12:24]
            l2_type=X_line_data[24:28]
                        
            if l2_type == "0800":               #IPv4
                packet,traffic_class_int,udp_ctr, tcp_ctr, icmp_ctr=ipv4_types(X_line_data,udp_ctr, tcp_ctr, icmp_ctr)   
            if l2_type == "0806":               #ARP
                arp_ctr=arp_ctr+1
                packet="ARP        "
                traffic_class_int=1
                arp_ctr=arp_ctr+1
                l3_hdr_len=0
                arp_code=X_line_data[40:44]
            if l2_type == "9000":
                packet="Loopback"
                traffic_class_int=4          
            if int("0x"+l2_type,0) < 1500:      #802.3
                packet,traffic_class_int,ieee_ctr=llc_types(X_line_data,ieee_ctr)

            '''
            if ctr%1000==0:
                print(traffic_class_int)
            '''
            traffic_class_int=str(traffic_class_int)
            Y[ctr]=traffic_class_int                             #Places the value of the ground truth into the proper Y index
            ctr=ctr+1
        
            l4_hdr,src_port_num,dst_port_num,l3_pid,src_ip,dst_ip="0","0","0","0","0","0"
            icmp_type_code,igmp_type_code,icmp6_type_code,pim_type,snap,arp_code="0","0","0","0","0","0"
            packet,X_line_data="",""
    print("Some label ctrs:",arp_ctr, icmp_ctr, ieee_ctr, tcp_ctr,udp_ctr)
    return Y

def preprocessor_main(features,classes,dataset_file_list,cleaned_file_list,X_test_file_list,Y_test_file_list):

    X_rows=0
    Y_rows=0
    Y_cols=1
    X_cols=features
    numpy_dir='c:\\python_code\\datasets_numpy\\'

    for i in range(len(dataset_file_list)):
        file_type=file_type_func(dataset_file_list[i])  #Determines file type.
        
        if file_type=="wireshark":
            source_file=dataset_file_list[i]
            X_outfile=cleaned_file_list[i]            

            print("Calling wireshark file cleaner.")
            data_cleaner(X_outfile, source_file, X_cols)
            print("Done. Outfile is:",X_outfile)
            
        X_source_file=cleaned_file_list[i]
        X_features_file=X_test_file_list[i]
        Y_labels_file=Y_test_file_list[i]

        print()
        print("Input file             :",X_source_file)
        print("Normalized feature file:",X_features_file)
        print("Output label file      :",Y_labels_file)
        print()

        X_rows, Y_rows=num_rows(X_source_file)              #Used to help build numpy arrays

        X,Y=numpy_X_Y(X_rows, X_cols, X_source_file, Y_rows, Y_cols)

        X_normalized=mean_normalize(X, features)     

        #if "w" in X_source_file:
        print("Calling fields and labels for:", X_source_file)
        Y=fields_and_labels(X_source_file, Y) #Processes source data to establish ground truth values.

        if i==0:
            #X_cnn_trainer=X_images
            X_mlp_trainer=X
            Y_labels=np.zeros((Y.shape[0],classes))
            for j in range(Y.shape[0]):   #This loop assigns 1s and 0s to the matrix of class labels in the shape [no. classes, no. packets]
                Y_val=int(Y[j][0])
                #print(j,Y_val)
                Y_labels[j][Y_val]=1
            Y_trainer=Y_labels
            print("Y_trainer shapes",Y_trainer.shape[0],Y_trainer.shape[1])

            np.save(numpy_dir+"X_trainer.npy",X_mlp_trainer)
            np.save(numpy_dir+"Y_labels.npy",Y_trainer)
            
        np.save(Y_labels_file,Y)
        np.save(X_features_file,X_normalized)



