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
    print()
   # Loop through the list and process each entry
    for interface in interfaces:
        # Use regex to capture the interface number, name, and status
        match = re.match(r'(\d+)\.(\S+) \[(.*)\]', interface)
        if match:
            number = match.group(1)
            name = match.group(2)
            status = match.group(3)

            # Create the dictionary entry for the interface in the desired format
            interface_str = f'Interface "{number}": "{name}" status: "{status}"'

            # Store in the dictionary using the format: Interface "number" as key
            interface_dict[f'Interface "{number}"'] = interface_str

    # Print the resulting dictionary
    for key, value in interface_dict.items():
        print(value)
    

def verify_interface(interface: str,interfaces:list):
    for i in interfaces:
        break
    return 0

if __name__ == "__main__":
   get_network_interfaces()

