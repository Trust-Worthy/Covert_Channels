

from configuration.system_config import get_network_interfaces
from configuration.system_config import print_interfaces

def welcome_message()-> None:
    print("_____________________________")
    print("_____________________________")
    print("_____________________________")
    print("Welcome to the Packet Menu. Select an option to get started or type Help")
    print("")


def print_capture_options() -> None:
    print("Capture Options")
    print("Please select an interface to capture network traffic on")
    print("_____________________________")
    print("_____________________________")

    user_interfaces: dict = get_network_interfaces()
    print_interfaces(user_interfaces)


def print_help_message()->None:
    print("You asked for help")
    print("The viable options are listed below")
    print_menu_options()