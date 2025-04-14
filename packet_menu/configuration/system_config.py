"""
 System Configuration


 Author: Trust-Worthy
    
    
"""
import subprocess
import re


def get_network_interfaces() -> dict[str,str]:

    result = subprocess.run(['tcpdump','-D'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode == 0:
        interfaces = []
        
        #Split the output by lines and  extract interface names
        for line in result.stdout.splitlines():
            line.strip(".")
            interfaces.append(line)

    return format_interfaces(interfaces)

def format_interfaces(interfaces: list[str]) -> dict[str,str]:
    interface_dict = {} 
    
    
    
    # Loop through the list and process each entry
    for i, interface in enumerate(interfaces):
        stripped_interface = re.sub(r'^[^.]*\.', '', interface)
        interface_dict[str(i)] = stripped_interface
   
    return interface_dict
    




if __name__ == "__main__":
   print_available_interfaces(get_network_interfaces())


