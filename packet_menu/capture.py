"""
Capture

Date: 11/25/2024

Main Function: Capture specific network packets based on user input and a specified number of packets.


Author: Trust Worthy


"""


import subprocess
from typing import Tuple
from pathlib import Path

count = 0




# (interface:str,protocol:str,quantity:int)
def construct_commands(result: tuple[str, str, int])->tuple[list[str],list[str],str]:
    user_interface,packet_type,quantity = result

    output_dir = Path("../captured_packets")

    pcap_file: str = str(output_dir / f"capture{count}.pcap")

    output_txt = str(output_dir / f"capture{count}.txt")

    output_dir.mkdir(parents=True,exist_ok=True)

    command_1:list[str] = [
         'tcpdump', # name of tool
         '-i',
         user_interface, 
         '-c', # specify number of packets to capture
         str(quantity),
         packet_type,
         '-w', # write packet to an output file
         pcap_file,
         '-xx', # see the entire packet from the link layer up to the data payload.
         '-tttt', # print timestamp for each packet in human readable format
         '-vv', # verbose output
         ]

    command_2:list[str] = [
         'tcpdump',
         '-r',
         pcap_file,
         '-xx',
         '-tttt',
         '-vv'
    ]
    return command_1,command_2,pcap_file,output_txt

def execute_commands(command_1:list[str,int],command_2:list[str],pcap_file:str,output_txt:str)->None:
        try:
            # Open the pcap file and write packet data to that file using subprocess
            with open(pcap_file, 'wb') as pcap_file_handle:
                result_1 = subprocess.run(command_1, stdout=pcap_file_handle, stderr=subprocess.PIPE, text=True)

            # Check if command_1 (capture command) was successful
            if result_1.returncode == 0:
                print(f"Capture successful. Output written to {pcap_file}")
            else:
                print("Error occurred during capture:")
                print(result_1.stderr)  # Display error message from tcpdump

            # Now read the pcap file and write the output to the .txt file
            with open(output_txt, 'w') as txt_file_handle:
                result_2 = subprocess.run(command_2, stdout=txt_file_handle, stderr=subprocess.PIPE, text=True)

            # Check if command_2 (reading and converting pcap) was successful
            if result_2.returncode == 0:
                print(f"PCAP file has been converted to {output_txt}")
            else:
                print("Error occurred during conversion:")
                print(result_2.stderr)  # Display error message from tcpdump

        except Exception as e:
            print(f"An error occurred: {e}")
    
            
def capture_main(result: tuple[str, str, int])->None:

    command_1,command_2,pcap_file,output_txt = construct_commands(result)

    execute_commands(command_1,command_2,pcap_file,output_txt)
    return 0

def main()->None:
    result = ('en0','icmp',1)
    capture_main(result)

if __name__ == "__main__":
     main()