def packet_choice(predictions):
    #print("In predictions packet choice.")
    #print("predicted shape",predicted.shape)
    #print()
    packet_class=[]
    packet_type="No match"
    packet_ctr=0
    predict_col=0
    no_match_ctr, arp_ctr,lldp_ctr, stp_ctr, cdp_ctr, dtp_ctr, gen_llc_ctr, isl_ctr, loopback_ctr=0,0,0,0,0,0,0,0,0
    misc_llc_ctr=0
    loop_ctr=0
    frag_ctr=0
    ipv4_ctr,ipv4_misc_ctr=0,0
    udp_ctr, quic_ctr, dns_ctr, dhcp_ctr, snmp_ctr, hsrp_ctr, ssdp_ctr, mdns_ctr=0,0,0,0,0,0,0,0
    nb_smb_ctr, nb_ns_ctr,db_ctr, ntp_ctr,llmnr_ctr, sip_ctr, udp_misc_ctr=0,0,0,0,0,0,0
    rtp_ctr, rtcp_ctr=0,0
    tcp_ctr, http_ctr, https_ctr, tcp_misc_ctr=0,0,0,0
    t80_ctr,t8080_ctr,t443_ctr,rdp_ctr=0,0,0,0
    http_data_ctr,https_data_ctr=0,0
    igmp_ctr, icmp_ctr, pim_ctr=0,0,0
    ipv6_ctr=0
    udp6_ctr, udp6_ssdp_ctr, udp6_llmnr_ctr, udp6_dhcp6_ctr, udp6_mdns_ctr, udp6_misc_ctr=0,0,0,0,0,0
    udp6_dns_ctr,wsdv6_ctr=0,0
    tcp6_ctr=0
    icmpv6_ctr, mulis_ctr=0,0
    udp_misc_ctr, tcp_misc_ctr=0,0
    ipv6_misc_ctr=0
    pvst_ctr=0
    
    pred_ctr_list=[]
    for i in predictions:
        if i==1:
            packet_type="ARP"
            arp_ctr=arp_ctr+1
        elif i==2:
            packet_type="ICMP"
            icmp_ctr=icmp_ctr+1
            ipv4_ctr=ipv4_ctr+1
        elif i==3:
            packet_type="IGMP"
            igmp_ctr=igmp_ctr+1
            ipv4_ctr=ipv4_ctr+1
        elif i==4:
            packet_type="Loopback"
            loop_ctr=loop_ctr+1
        #elif i==5:
        #    packet_type="LLDP"
        #    lldp_ctr=lldp_ctr+1
        elif i==5:
            packet_type="STP"
            stp_ctr=stp_ctr+1
            gen_llc_ctr=gen_llc_ctr+1
        elif i==6:
            packet_type="CDP"
            gen_llc_ctr=gen_llc_ctr+1
            cdp_ctr=cdp_ctr+1
        elif i==7:
            packet_type="DNS"
            ipv4_ctr=ipv4_ctr+1
            udp_ctr=udp_ctr+1
            dns_ctr=dns_ctr+1
        elif i==8:
            packet_type="DHCP"
            udp_ctr=udp_ctr+1
            ipv4_ctr=ipv4_ctr+1
            dhcp_ctr=dhcp_ctr+1
        elif i==9:
            packet_type="SSDP"
            ipv4_ctr=ipv4_ctr+1
            udp_ctr=udp_ctr+1
            ssdp_ctr=ssdp_ctr+1
        elif i==10:
            packet_type="NBNS"
            ipv4_ctr=ipv4_ctr+1
            udp_ctr=udp_ctr+1
            nb_ns_ctr=nb_ns_ctr+1
        elif i==11:
            packet_type="IPv4 80"
            tcp_ctr=tcp_ctr+1
            t80_ctr=t80_ctr+1
            ipv4_ctr=ipv4_ctr+1
        elif i==12:
            packet_type="IPv4 port 8080"
            ipv4_ctr=ipv4_ctr+1
            tcp_ctr=tcp_ctr+1
            t8080_ctr=t8080_ctr+1
        elif i==13:                       
            packet_type="IPv4 port 443"
            tcp_ctr=tcp_ctr+1
            t443_ctr=t443_ctr+1
            ipv4_ctr=ipv4_ctr+1
        else:
            packet_type="Other"
            no_match_ctr=no_match_ctr+1
        packet_ctr=packet_ctr+1
        packet_class=[]
        packet_type=""
    
    print()
    print("Total pkts    :",packet_ctr)
    print("IPv4 pkts     :",ipv4_ctr)
    print("UDP pkts      :",udp_ctr)
    print("TCP pkts      :",tcp_ctr)
   
    print("0-Other       :",no_match_ctr)
    print("1-ARP pkts    :",arp_ctr)
    print("2-ICMP pkts   :",icmp_ctr)
    print("3-IGMP pkts   :",igmp_ctr)
    print("4-LOOP        :",loop_ctr)
    print("5-STP         :",stp_ctr)
    print("6-CDP         :",cdp_ctr)
    print("7-DNS         :",dns_ctr)
    print("8-DHCP        :",dhcp_ctr)
    print("9-SSDP        :",ssdp_ctr)
    print("10-NBNS       :",nb_ns_ctr)
    print("11-TCP 80     :",t80_ctr)
    print("12-TCP 8080   :",t8080_ctr)       
    print("13-TCP 443    :",t443_ctr)
    print()

def accuracy(predictions, Y_test):
    accuracy_ctr=0
    #print("Predictions shape",predictions.shape)
    total=predictions.shape[0]
    #print("Value of total:",total)
    for i in range(predictions.shape[0]):
        #print(i)
        #print(predictions[i],Y_test[i])
        #print(predictions[i],Y_test[0][i])
        if int(predictions[i])==int(Y_test[0][i]):
            accuracy_ctr=accuracy_ctr+1
        #else:
        #    print("Incorrect prediction:",int(predictions[i]),"Ground truth:",int(Y_test[0][i]))
    print("###############################################")
    #print()
    print("Total predictions:",total, "Accuracy ctr:",accuracy_ctr)
    print("Accuracy of predictions:",accuracy_ctr/total)
    #print()
    print("###############################################")
