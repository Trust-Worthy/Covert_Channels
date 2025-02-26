"""
Menu

Date 11-23-2024

Main Function:

'''
arp request 
arp reply
icmp request 
icmp reply
dns 
http
tls
quic
other 

'''

Author: Trust-Worthy

"""
import os

from packet_menu.configuration.system_config import get_network_interfaces
from packet_menu.configuration.system_config import print_interfaces
from typing import Tuple, Union
from packet_menu.metrics.packet_stats import parse_packet_file
from pathlib import Path
from packet_menu.capture_data.capture import capture_main

PREV_CAPTURES = set()

def print_help_message()->None:
    print("You asked for help")
    print("The viable options are listed below")
    print_menu_options()


def welcome_message()-> None:
    print("_____________________________")
    print("_____________________________")
    print("_____________________________")
    print("Welcome to the Packet Menu. Select an option to get started or type Help")
    print("")

def capture_options()->Tuple[str,int]:
    print("Capture Options")
    print("Please select an interface to capture network traffic on")
    print("_____________________________")
    print("_____________________________")

    user_interfaces: dict = get_network_interfaces()
    print_interfaces(user_interfaces)


    desired_interface: str = input("Format: 'interface name' ex. -->en0:\n-->")
    while desired_interface not in user_interfaces:
        print(f" {desired_interface} is invalid. Try again")
        print_interfaces(user_interfaces)
        desired_interface: str = input("Format: 'interface name' ex. -->en0:\n-->")

    
    num_packets: int = get_num_user_packets()
    capture_name: str = input("Please give a name for your capture. Name will be used to name the pcap and .txt file\n-->")
    while capture_name in PREV_CAPTURES:
        print("Name of capture has already been used. Please enter a different name.")
        capture_name: str = input("Please give a name for your capture. Name will be used to name the pcap and .txt file\n-->")

    print("Capturing {} packets on {}".format(num_packets,desired_interface))
    capture_main(capture_name, desired_interface,num_packets)
def get_num_user_packets()->int:
    print("Please specify a certian number of packets to capture\n")

    while True:
        try:
            # Prompt the user for input
            # Edit: I am only supposed to be getting the number of packets. Not a specific type of packet.
            quantity:int = int(input("Format: -->'# of packets' ex. -->10\n-->"))

            if quantity <= 0:
                print("The number of packets must be a positive integer.\n")
                continue  # Retry the loop if the number is not positive

            return quantity
        except ValueError:
            # If an error occurs (e.g., wrong format or non-integer input)
            print("Incorrect type entered. Please enter integer number of packets.\n")
             # Use continue to retry the loop without returning to the function
            continue

def print_clean_packets_options()->None:
    return None
def exit_program()->None:
    print("exiting program...")
    exit()
def print_packet_stats_options()->None:
    path = Path('captured_packets')

    # Gather all .txt files in the directory
    txt_files = list(path.glob('*.txt'))

    # If no files are found, inform the user and exit
    if not txt_files:
        print("No .txt files found in the directory.")
        return

    file_options = [file.name for file in txt_files]
    file_options_set = set(file_options)

    print("Please select a file to be analyzed:")
    for i, file_name in enumerate(file_options, 1):
        print(f"{i}. {file_name}")

    while True:
        user_file_opt = input("Enter the name corresponding to your file option: ").strip()
        
        if user_file_opt in file_options_set:
            break
        else:
            print("That is not a valid file option. Please try again!")

    file_path = path / user_file_opt
    parse_packet_file(file_path)


def print_full_analysis_options()->None:
    """_summary_

    Returns:
        _type_ -- _description_
    """    
    return None

def print_menu_options()->str:

    #capture
        # What type of packet do you want to capture?
    print("Menu Options")
    print("Option A: Capture -> Displays options for capturing packets")
    print("Option B: Clean Packets -> Displays options for cleaning a file with packets previously captured")
    print("Option C: Packet Stats -> Displays options for doing statistics on packets previously captured")
    print("Option D: Full Analysis -> Displays options for Capturing packet, cleaning the packets, and then doing statistics on the packets")
    print("Help: Displays the help menu")
    print("Exit: Exit program and terminate.\n")
    
    user_option: str = input("Enter option:\n-->")

    process_user_input(option=user_option)

def process_user_input(*,option: str)->None:
    option = option.lower()
    option_dict = {
        "option a":capture_options, # returns a tuple
        "option b":print_clean_packets_options,
        "option c":print_packet_stats_options,
        "option d":print_full_analysis_options,
        "help":print_help_message,
        "exit":exit_program,
    }

    while option not in option_dict:
        print(f"Invalid option: {option}. Please try again.")
        option = input("Enter an option:\n-->").lower()
    


    returned_func = option_dict[option]
    returned_func()
    

def display_menu()->None:

    # Show the welcome message
    welcome_message()

    #Print the menu options. Get the input from the user.
    user_option = print_menu_options()

    
    """
    Control Flow:

    Print menu options --> Process user input --> Func that handles specific option


    """




if __name__ == "__main__":
    display_menu()