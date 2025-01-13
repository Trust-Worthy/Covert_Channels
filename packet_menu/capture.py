"""
Capture

Date: 11/25/2024

Main Function: Capture specific network packets based on user input and a specified number of packets.


Author: Trust Worthy


"""


import subprocess
from typing import Tuple
from pathlib import Path





# (interface:str,protocol:str,quantity:int)
def construct_commands(capture_name:str,user_interface:str,num_packets:int)->tuple[list[str],list[str],str,str]:

    output_dir = Path("captured_packets/")

    pcap_file: str = str(output_dir / f"capture{capture_name}.pcap")

    output_txt = str(output_dir / f"capture{capture_name}.txt")

    output_dir.mkdir(parents=True,exist_ok=True)

    command_1:list[str] = [
         'sudo',
         'tcpdump', # name of tool
         '-i',
         user_interface, 
         '-c', # specify number of packets to capture
         str(num_packets),
         #packet_type,
         '-w', pcap_file,# write packet to an output file 
         '-xx', # display raw hex format.
         '-tttt', # print timestamp for each packet in human readable format
         #'-vv', # verbose output
         ]

    command_2:list[str] = [
         'sudo',
         'tcpdump',
         '-r', pcap_file, # read the saved pcap file
         '-xx',
         '-tttt',
         #'-vv' #verbose output
    ]

    return command_1,command_2,pcap_file,output_txt

def execute_commands(command_1:list[str],command_2:list[str],pcap_file:str,output_txt:str)->None:
        """_summary_

        :param command_1: _description_
        :type command_1: list[str,int]
        :param command_2: _description_
        :type command_2: list[str]
        :param pcap_file: _description_
        :type pcap_file: str
        :param output_txt: _description_
        :type output_txt: str
        """        
        
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

        
def capture_main(capture_name:str,desired_interface:str,num_packets:int)->None:

    command_1,command_2,pcap_file,output_txt = construct_commands(capture_name,desired_interface,num_packets)

    execute_commands(command_1,command_2,pcap_file,output_txt)

def main()->None:
    
    result = ('en0','icmp',2)
    capture_main(result)

if __name__ == "__main__":
     main()