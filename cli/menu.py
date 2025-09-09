"""
menu.py            → Shows menu and navigation
├── input_handlers → Ask & validate inputs
├── commands       → Call the actual logic
└── output_handlers→ Show results

"""
from typing import Callable

from cli.output_handlers import print_welcome_message, print_menu_options, print_help_message
from input_handlers import get_user_main_menu_selection

from commands import capture_packets, clean_packets, calculate_packets_stats, exit_program

def main():
    print_welcome_message()

    menu_options: dict[str, Callable[[], None]] = {
        
        "1":capture_packets, # returns a tuple
        "2":clean_packets,
        "3":calculate_packets_stats,
        "help":print_help_message,
        "exit":exit_program,
    }

    while True:
        
        print_menu_options()
        
    
        while True:
            user_selection: str = get_user_main_menu_selection()
            if user_selection in menu_options:
                
                ### Call that function
                call_command = menu_options[user_selection]
                call_command()
                break
            else:
                print(f"Invalid option: {user_selection}. Please try again.")
                continue

        

if __name__ == "__main__":
    main()