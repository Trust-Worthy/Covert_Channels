

from configuration.system_config import get_network_interfaces
from configuration.system_config import print_interfaces

def welcome_message()-> None:
    print("_____________________________")
    print("Welcome to C^3 (Covert Channel Capture).\nSelect an option to get started or type Help.")
    print("")


def print_interface_options() -> dict[str,str]:
    print("_____________________________")
    print("Capture Options")
    print("Please select an interface to capture network traffic on.")

    
    user_interfaces: dict = get_network_interfaces()
    print("_____________________________")
    print_interfaces(user_interfaces)

    return user_interfaces

def get_user_interface_choice(user_interfaces: dict[str,str]) -> str:
    
   
    while True:
        desired_interface: str = input("==> ")

        if desired_interface in user_interfaces:
            break
            
        else:
            print(f" {desired_interface} is invalid. Try again")
            print_interfaces(user_interfaces)
            continue
    
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

def print_help_message()->None:
    print("You asked for help")
    print("The viable options are listed below")
    print_menu_options()



def exit_program()->None:
    print("exiting program...")
    exit()

def check_if_exit(user_input: str) -> bool:

    try:
        if user_input.strip() == "exit":
            True
    except ValueError:
        return False
