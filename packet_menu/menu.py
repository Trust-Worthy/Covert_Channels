"""
Menu

Date 11-23-2024

Main Function:



Author: Trust-Worthy

"""
import os
from system_config import get_network_interfaces
from system_config import verify_interface
from system_config import print_interfaces

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

def print_capture_options()->tuple:
    print("Capture Options")
    print("Please select an interface to capture network traffic on")
    print("_____________________________")
    print("_____________________________")

    user_interfaces: dict = get_network_interfaces()
    print_interfaces(user_interfaces)


    user_interface: str = input("Format: 'interface name' ex. en0:\n")
    while verify_interface(user_interface,user_interfaces) == False:
        verify_interface(user_interface,user_interfaces)
    
    print("Please specify packet type and # of packets to capture separated by a space\n")

    while True:
        try:
            # Prompt the user for input
            packet_type, num_packets = input("Format: 'packet type' '# of packets' ex. ICMP 10:\n").split(" ")
            
            # Try to convert num_packets to an integer
            num_packets:int = int(num_packets)
            
            # If everything is correct, break the loop
            break
        except ValueError:
            # If an error occurs (e.g., wrong format or non-integer input)
            print("Error: Please enter a valid packet type and number of packets.\n")
        

    print("Capturing {} {} packets on {}".format(num_packets,packet_type,user_interface))
    return packet_type,num_packets

def print_clean_packets_options()->None:
    return 0

def print_packet_stats_options()->None:
    return 0

def print_full_analysis_options()->None:
    return 0

def print_menu_options()->None:

    #capture
        # What type of packet do you want to capture?
    print("Menu Options")
    print("Option A: Capture -> Displays options for capturing packets")
    print("Option B: Clean Packets -> Displays options for cleaning a file with packets previously captured")
    print("Option C: Packet Stats -> Displays options for doing statistics on packets previously captured")
    print("Option D: Full Analysis -> Displays options for Capturing packet, cleaning the packets, and then doing statistics on the packets")
def get_user_option()->str:
    print()
    print()
    user_option: str = input("Enter option: ")

    return user_option

def process_user_input(option: str):
    option = option.lower()
    option_dict = {
        "option a":print_capture_options,
        "option b":print_clean_packets_options,
        "option c":print_clean_packets_options,
        "option d":print_full_analysis_options,
        "help":print_help_message,
    }
    # Print correct options or Invalid if key isn't found in the dictionary
    option_dict.get(option,lambda:"Invalid Option please try again\n")()

def display_menu()->None:
    welcome_message()
    print_menu_options()

    
    process_user_input(get_user_option())








if __name__ == "__main__":
    display_menu()