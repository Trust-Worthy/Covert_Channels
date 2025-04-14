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


from typing import Tuple, Union

from pathlib import Path
from capture_data.capture import capture_packets

def get_existing_captures() -> set[str]:
    directory_path = Path("../captured_packets")
    file_names = {f.name for f in directory_path.iterdir() if f.is_file()}

    return file_names

    
   


def print_clean_packets_options()->None:
    return None





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
    print("1: Capture -> Displays options for capturing packets")
    print("2: Clean Packets -> Displays options for cleaning a file with packets previously captured")
    print("3: Packet Stats -> Displays options for doing statistics on packets previously captured")
    print("4: Full Analysis -> Displays options for Capturing packet, cleaning the packets, and then doing statistics on the packets")
    print("Help: Displays the help menu")
    print("Exit: Exit program and terminate.\n")
    
    user_option: str = input("Enter option:\n-->")

    process_user_input(option=user_option)

def process_user_input(*,option: str)->None:
    
    option = option.strip().lower()
    option_dict = {
        "1":capture_options, # returns a tuple
        "2":print_clean_packets_options,
        "3":print_packet_stats_options,
        "4":print_full_analysis_options,
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