"""
Menu

Date 11-23-2024

Main Function:



Author: Trust-Worthy

"""
from packet_menu.system_config import get_network_interfaces
from packet_menu.system_config import verify_interface
from packet_menu.system_config import print_interfaces

def print_help_message():
    print("You asked for help")
    print("The viable options are listed below")
    print_menu_options()


def welcome_message():
    print("_____________________________")
    print("_____________________________")
    print("_____________________________")
    print("Welcome to the Packet Menu")
    print("Select an option to get started or type Help")

def print_capture_options():
    print("Capture Options")
    print("Please select an interface to capture network traffic on")
    print("_____________________________")
    print("_____________________________")

    print_interfaces(get_network_interfaces())


    user_interface: str = input("The format should be: 'interface name' ex. en0")
    verify_interface(user_interface)

    

    return 0

def print_clean_packets_options():
    return 0

def print_packet_stats_options():
    return 0

def print_full_analysis_options():
    return 0

def print_menu_options():

    #capture
        # What type of packet do you want to capture?
    print("Menu Options")
    print("Option A: Capture -> Displays options for capturing packets")
    print("Option B: Clean Packets -> Displays options for cleaning a file with packets previously captured")
    print("Option C: Packet Stats -> Displays options for doing statistics on packets previously captured")
    print("Option D: Full Analysis -> Displays options for Capturing packet, cleaning the packets, and then doing statistics on the packets")

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

def display_menu():
    welcome_message()
    print_menu_options()

    user_option: str = input("Enter option: ")
    process_user_input(user_option)








if __name__ == "__main__":
    display_menu()