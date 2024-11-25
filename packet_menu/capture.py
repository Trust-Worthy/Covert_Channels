"""
Capture

Date: 11/25/2024

Main Function: Capture specific network packets based on user input and a specified number of packets.


Author: Trust Worthy


"""


import subprocess
from typing import Tuple
from pathlib import Path

count = 0




# (interface:str,protocol:str,quantity:int)
def construct_command(result: tuple[str, str, int])->tuple[list[str],str]:
    user_interface,packet_type,quantity = result

    output_dir = Path("../captured_packets")

    output_file: str = str(output_dir / f"capture{count}.pcap")

    output_dir.mkdir(parents=True,exist_ok=True)

    command:list[str] = [
         'tcpdump',
         '-i',
         user_interface, 
         '-c', 
         str(quantity),
         packet_type,
         '-w',output_file]

    return command,output_file

def execute_command(command:list[str,int],output_file:str)->None:
    try:

        # Run the command using subprocess
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check if the command was successful
        if result.returncode == 0:
            print(f"Capture successful. Output written to {output_file}")
        else:
            print("Error occurred during capture:")
            print(result.stderr)  # Display any error message from tcpdump
        
    except Exception as e:
            print(f"An error occurred: {e}")
            
def capture_main(result: tuple[str, str, int])->None:

    command,output_file = construct_command(result)

    execute_command(command,output_file)
    return 0

def main()->None:
    result = ('en0','icmp',1)
    capture_main(result)

if __name__ == "__main__":
     main()