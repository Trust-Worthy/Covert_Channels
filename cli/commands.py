
import subprocess
from typing import Union

import os, re

from core.protocols.undefined_layer.undefined_protocol import OTHER_PROTOCOL
from core.protocols.layer_2_protocols.ethernet import Ethernet_Frame
from core.protocols.layer_3_protocols.arp import ARP_PACKET
from core.protocols.layer_3_protocols.icmp import ICMP_MESSAGE
from core.protocols.layer_3_protocols.ip import IP_HEADER
from core.protocols.layer_4_protocols.tcp import TCP_HEADER
from core.protocols.layer_4_protocols.udp import UDP_HEADER
from core.protocols.application_layer.dns import DNS
from core.protocols.application_layer.http import HTTP
from core.protocols.application_layer.https import HTTPS
from core.protocols.application_layer.tls import TLS_Packet
from core.protocols.application_layer.quic import QUIC_HEADER



        
def capture_packets()->None:
    """
    Capture packets function interfaces with all necessary functions to take in user input for a 
    user-defined packet capture.
    """

    available_interfaces: dict = get_network_interfaces()

    while True:
        output_handlers.print_available_interfaces(available_interfaces)
        user_interface_choice: str = input_handlers.get_user_interface_choice(user_interfaces=available_interfaces)
        if user_interface_choice in available_interfaces:
            break
        elif user_interface_choice.strip() == "exit":
            exit_program()
        else:
            print(f" {user_interface_choice} is invalid. Try again.")
            continue
    
    num_packets_to_capture: int = input_handlers.get_num_packets_to_capture()

    ### These places where I'm taking in input are where secure software practices come into play!!
    name_of_capture: str = input_handlers.get_name_of_capture()


    command_1,command_2,pcap_file,output_txt = construct_tcpdump_capture_commands(name_of_capture,user_interface=user_interface_choice,num_packets=num_packets_to_capture)

    run_tcpdump_capture_commands(command_1,command_2,pcap_file,output_txt)

    

    print(f"{name_of_capture} is capturing {num_packets_to_capture} on interface {user_interface_choice}...")





def create_protocols(file_path) ->list[Union[Ethernet_Frame,ARP_PACKET,ICMP_MESSAGE,IP_HEADER,TCP_HEADER, UDP_HEADER,OTHER_PROTOCOL]]: 
    
    pass

def calculate_packets_stats() -> None:
    print_packet_stats_options()

    pass



def exit_program()->None:
    print("exiting program...")
    exit()

if __name__ == "__main__":

    clean_packets()