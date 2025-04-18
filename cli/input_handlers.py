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


from typing import Optional

from pathlib import Path


def get_existing_captures() -> set[str]:
    print("Finding existing captures...")

    directory_path = Path("../captured_packets")
    file_names = {f.name for f in directory_path.iterdir() if f.is_file()}


    for file in file_names:
        print(file)


def get_user_interface_choice(user_interfaces: dict[str,str]) -> str:
   
    desired_interface: str = input("==> ")
        
    return desired_interface

def get_num_packets_to_capture()->int:

    while True:
        try:
            # Prompt the user for input
            # Edit: I am only supposed to be getting the number of packets. Not a specific type of packet.
            message: str = "Please specify the # of packets to capture:"
            quantity:int = int(input(f"{message}\n--> "))

            if check_if_exit(quantity):
                exit_program()
            elif quantity <= 0:
                print("The number of packets must be a positive integer.\n")
                continue  # Retry the loop if the number is not positive
                
            return quantity
        except ValueError:
            # If an error occurs (e.g., wrong format or non-integer input)
            print("Incorrect type entered. Please enter integer number of packets.\n")
             # Use continue to retry the loop without returning to the function
            continue

def get_name_of_capture() -> str:
    message: str = "Please give a name for your capture."
    capture_name: str = input(f"{message}\n==> ")
    
    while capture_name in PREV_CAPTURES:
        print("Name of capture has already been used. Please enter a different name.")
        capture_name: str = input("Please give a name for your capture. Name will be used to name the pcap and .txt file\n-->")

    print("Capturing {} packets on {}".format(num_packets,desired_interface))
    capture_main(capture_name, desired_interface,num_packets)


def get_user_main_menu_selection() -> str:
    user_option: str = input("Select Menu Option\n==> ")

    
    ### Secure software dev practices belong here with input sanitization   
    user_option = user_option.strip().lower()

    return user_option


if __name__ == "__main__":
    pass