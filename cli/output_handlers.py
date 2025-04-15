

from configuration.system_config import get_network_interfaces

def print_welcome_message()-> None:
    print("_____________________________")
    print("Welcome to C^3 (Covert Channel Capture).\nSelect an option to get started or type Help.")
    print("")

def print_menu_options()->str:

    print("Menu Options")
    print("1: Capture ==> capture new packets.")
    print("2: Clean Packets ==> clean previously captured packets.")
    print("3: Packet Stats ==>  perform statistics on previously cleaned packets.")
    print("Help: Displays the help menu")
    print("Exit: Exit program and terminate.\n")

def print_available_interfaces() -> dict[str,str]:
    print("_____________________________")
    print("Capture Options")
    print("Please select an interface to capture network traffic on.")
    
    user_interfaces: dict = get_network_interfaces()

    print("_____________________________")
    for key, value in user_interfaces.items():
        print(f'{key}: {value}')

    return user_interfaces


def print_help_message()->None:
    print("You asked for help.")
    print("The viable options are listed below.")
    print_menu_options()

def print_clean_packets_options()->None:
    pass


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



def format_interfaces(interfaces: list[str]) -> dict[str,str]:
    interface_dict = {} 
    
    
    
    # Loop through the list and process each entry
    for i, interface in enumerate(interfaces):
        stripped_interface = re.sub(r'^[^.]*\.', '', interface)
        interface_dict[str(i)] = stripped_interface
   
    return interface_dict
