"""
menu.py            → Shows menu and navigation
├── input_handlers → Ask & validate inputs
├── commands       → Call the actual logic
└── output_handlers→ Show results

"""

import input_handlers, output_handlers, commands


client_interfaces = []

def run_capture():
    available_interfaces = print_interface_options()
    user_interface_choice = get_user_interface_choice()
    num_packets_to_capture = get_num_packets_to_capture()
    name_of_capture = get_name_of_capture()

    print(f"{name_of_capture} is capturing {num_packets_to_capture} on interface {user_interface_choice}...")

    capture_packets(name_of_capture,user_interface_choice,num_packets_to_capture)


def main():

    #Display the menu
    display_menu()

    # Ask the user to select an option and process it
    execute_option()



if __name__ == "__main__":
    main()