
import subprocess
import input_handlers, output_handlers
from typing import Optional, Union
from core.processing.parser import Packet_parser
from pathlib import Path
import os, re

from core.protocols.all_protocols import *

def construct_tcpdump_capture_commands(capture_name:str,user_interface:str,num_packets:int)->tuple[list[str],list[str],str,str]:

    output_dir = Path("captured_packets/")

    pcap_file: str = str(output_dir / f"capture{capture_name}.pcap")

    output_txt = str(output_dir / f"capture{capture_name}.txt")

    output_dir.mkdir(parents=True,exist_ok=True)

    command_1:list[str] = [
         'sudo',
         'tcpdump', # name of tool
         '-i',
         user_interface, 
         '-n', # removes the hostnames so that more DNS resolutions are required
         '-c', # specify number of packets to capture
         str(num_packets),
         '-w', pcap_file,# write packet to an output file 
         '-x', # display raw hex format.
         #'-tttt',
         '--time-stamp-precision=micro',#ttt', # print timestamp for each packet in human readable format
         #'-vv', # verbose output
         ]

    command_2:list[str] = [
         'sudo',
         'tcpdump',
         '-n',
         '-r', pcap_file, # read the saved pcap file
         '-x',
         '--time-stamp-precision=micro',#ttt', prints timestamps
    ]

    return command_1,command_2,pcap_file,output_txt


def run_tcpdump_capture_commands(command_1:list[str],command_2:list[str],pcap_file:str,output_txt:str)->None:
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


def clean_packets()-> None:

    available_files = output_handlers.print_clean_packets_options()

    ### TO-DO ### 
    # allow user to choose what files to clean

    output_directory = Path("../captures/cleaned_captures")

    for file in available_files.values():

        clean_file(file, output_dir=output_directory)

def clean_file(file_path: str, output_dir: str):
    protocol_set = {b"UDP", b"ICMP", b"ICMP6", b"TCP", b"TLS", b"IP", b"ARP", b"ETHERNET"}
    packet_start_pattern = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d{6} .+")
    
    with open(file_path, "r") as uncleaned_file:
        cleaned_data: list[bytes] = []  # Data will be stored as bytes
        packet_metadata: list[bytes] = []  # Metadata will be stored as bytes
        current_packet_data: list[bytes] = []  # Store data for the current packet

        for line in uncleaned_file:
            # Check for the start of a new packet based on timestamp pattern
            if packet_start_pattern.match(line):
                # If a packet was being collected, save it
                if current_packet_data:
                    # Combine metadata and packet data into one byte sequence for each packet
                    cleaned_data.append(b"\n".join(packet_metadata + current_packet_data))
                
                # Clear previous packet data and metadata for the next packet
                current_packet_data = []
                packet_metadata = []
                
                # Capture the timestamp line as metadata
                packet_metadata.append(line.strip().encode())  # Store metadata as bytes
            else:
                # Match lines containing protocol info (e.g., "UDP", "ICMP6")
                for protocol in protocol_set:
                    if protocol in line.encode():  # Convert line to bytes for matching
                        packet_metadata.append(line.strip().encode())  # Store metadata as bytes

                # Skip the lines containing hexadecimal data offsets (e.g., "0x0000:")
                if line.startswith("0x"):
                    # Skip the offset and extract just the hex data (remove the "0x0000:" part)
                    hex_data = line.split(":")[1].strip()  # Extract hex data
                    byte_data = bytes.fromhex(hex_data)  # Convert hex data to bytes
                    current_packet_data.append(byte_data)  # Add byte data to current packet

                # Optionally, keep the raw byte data if it's not part of the "0x" offset
                elif len(line.strip()) == 47 and not line.startswith("0x"):  # Check for raw byte-like lines
                    byte_data = bytes.fromhex(line.strip())  # Convert the line to bytes
                    current_packet_data.append(byte_data)  # Add byte data to current packet

        # If there was a packet being collected at the end of the file, save it
        if current_packet_data:
            cleaned_data.append(b"\n".join(packet_metadata + current_packet_data))

        # Write the cleaned data to a new file in the cleaned_captures directory
        cleaned_filename = os.path.join(output_dir, "cleaned" + os.path.basename(file_path))

        with open(cleaned_filename, "wb") as cleaned_file:  # Open in binary write mode
            cleaned_file.write(b"\n".join(cleaned_data))  # Write bytes to the file
            print(f"Cleaned file saved as {cleaned_filename}")

# Example usage
# clean_file("path/to/uncleaned_file.txt", "path/to/output_dir")


def create_protocols(file_path) ->list[Union[Ethernet_Frame,ARP_PACKET,ICMP_MESSAGE,IP_HEADER,TCP_HEADER, UDP_HEADER,OTHER_PROTOCOL]]: 

    pass

def calculate_packets_stats() -> None:
    output_handlers.print_packet_stats_options()

    pass
def get_network_interfaces() -> dict[str,str]:

    result = subprocess.run(['tcpdump','-D'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        interfaces = []
        
        #Split the output by lines and  extract interface names
        for line in result.stdout.splitlines():
            line.strip(".")
            interfaces.append(line)

    return output_handlers.format_interfaces(interfaces)


def exit_program()->None:
    print("exiting program...")
    exit()

if __name__ == "__main__":

    clean_packets()