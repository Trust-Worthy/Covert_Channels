#This set of functions provides the labels based on l2_type and l3_pid

def ipv4_types(X_line_data,udp_ctr, tcp_ctr, icmp_ctr):
    traffic_class_int=0
    packet="No match"
    flags=X_line_data[40:44]
    l3_pid=X_line_data[46:48]
    l3_hdr_len=20
    src_ip=X_line_data[52:60]
    dst_ip=X_line_data[60:68]
    if l3_pid == "11":                  #UDP
        l4_hdr=X_line_data[68:84]
        src_port_num=X_line_data[68:72]
        dst_port_num=X_line_data[72:76]
        udp_info_1=X_line_data[84:86]
        udp_info_2=X_line_data[86:88]
        if dst_port_num=="0035" or src_port_num=="0035":
            packet="IPv4 UDP DNS"
            traffic_class_int=7
            udp_ctr=udp_ctr+1
        if dst_port_num=="0043" or dst_port_num=="0043" or dst_port_num=="0044" or src_port_num=="0044":
            packet="IPv4 UDP DHCP"
            traffic_class_int=8
            udp_ctr=udp_ctr+1
        if src_port_num=="076c" or dst_port_num=="076c":
            packet="IPv4 UDP SSDP"
            traffic_class_int=9
            udp_ctr=udp_ctr+1
        if src_port_num=="14e9" or dst_port_num=="14e9":
            packet="IPv4 UDP MDNS"
            traffic_class_int=7
            udp_ctr=udp_ctr+1
        if src_port_num=="0089" or dst_port_num=="0089":
            packet="IPv4 UDP Netbios NS"
            traffic_class_int=10
            udp_ctr=udp_ctr+1
        if src_port_num=="14eb" or dst_port_num=="14eb":
            packet="IPv4 UDP LLMNR"
            traffic_class_int=7
            udp_ctr=udp_ctr+1

    if l3_pid == "06":                  #TCP
        l4_hdr=X_line_data[68:108]
        src_port_num=X_line_data[68:72]
        dst_port_num=X_line_data[72:76]
        
        if dst_port_num=="01bb" or src_port_num=="01bb":
            packet="IPv4 TCP 443"
            traffic_class_int=13
            tcp_ctr=tcp_ctr+1
        if dst_port_num=="0050" or src_port_num=="0050":
            packet="IPv4 TCP 80"
            traffic_class_int=11
            tcp_ctr=tcp_ctr+1
        if dst_port_num=="1f90" or src_port_num=="1f90":
            packet="IPv4 TCP 8080"
            traffic_class_int=12
            tcp_ctr=tcp_ctr+1

    if l3_pid == "01":                  #ICMP
        icmp_type_code=X_line_data[68:72]
        packet="IPV4 ICMP"
        traffic_class_int=2
        icmp_ctr=icmp_ctr+1

    if l3_pid == "02":                  #IGMP
        packet="IPV4 IGMP  "
        traffic_class_int=3
        igmp_type_code=X_line_data[68:70]

    return packet, traffic_class_int, udp_ctr, tcp_ctr, icmp_ctr

def llc_types(X_line_data,ieee_ctr):
    traffic_class_int=0
    packet="No match"
    dsapssap=X_line_data[28:32]
    l3_hdr_len=0
    if dsapssap == "4242":
        packet="802.3 STP"
        traffic_class_int=5
        ieee_ctr=ieee_ctr+1
        
    if dsapssap == "aaaa":
        llc_pid=X_line_data[40:44]
        if llc_pid == "2000":
            packet="802.3 CDP"
            traffic_class_int=6
            ieee_ctr=ieee_ctr+1

    
    return packet, traffic_class_int, ieee_ctr
