"""
menu.py            → Shows menu and navigation
├── input_handlers → Ask & validate inputs
├── commands       → Call the actual logic
└── output_handlers→ Show results

"""
from typing import Callable

from . import 




def main():
    print_welcome_message()

    menu_options: dict[str, Callable[[], None]] = {
        
        "1":commands.capture_packets, # returns a tuple
        "2":commands.clean_packets,
        "3":commands.calculate_packets_stats,
        "help":output_handlers.print_help_message,
        "exit":commands.exit_program,
    }

    while True:
        
        output_handlers.print_menu_options()
        
    
        while True:
            user_selection: str = input_handlers.get_user_main_menu_selection()
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