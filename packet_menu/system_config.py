"""
 System Configuration

 Date: 11-18-2024


 Main Function:


 Dependencies:



 Author: Trust-Worthy
    
    
"""
import subprocess
import re

interface_width = 15  # Adjust the number based on the longest interface name
status_width = 40


def get_network_interfaces() -> dict:

    result = subprocess.run(['tcpdump','-D'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        interfaces = []
        
        #Split the output by lines and  extract interface names
        for line in result.stdout.splitlines():
            line.strip(".")
            interfaces.append(line)

    return format_interfaces(interfaces)

def format_interfaces(interfaces: list) -> dict:
    interface_dict = {} 
    print()
    
    # Loop through the list and process each entry
    for interface in interfaces:
        # Use regex to capture the interface number, name, and status
        match = re.match(r'(\d+)\.(\S+) \[(.*)\]', interface)
        if match:
            name = match.group(2)
            status = match.group(3)

            # Add the interface name as the key and the status as the value in the dictionary
            interface_dict[name] = status

   
    return interface_dict
    
def print_interfaces(interfaces:dict)->None:
   # Print the resulting dictionary in the format: key: value
    for key, value in interfaces.items():
        print(f'{key}: {value}')

def verify_interface(interface: str,interfaces:list)->bool:
    if interface in interfaces:
        print("interface {} exists...".format(interface))
        return True
    else:
        print(" {} is invalid. Try again".format(interface))
        print_interfaces(interfaces)
        return False

    
    

if __name__ == "__main__":
   print_interfaces(get_network_interfaces())

   verify_interface("en0",get_network_interfaces())

