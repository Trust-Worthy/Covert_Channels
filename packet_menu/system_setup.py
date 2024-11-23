"""
 System Setup

 Date: 11-18-2024


 Main Function:


 Dependencies:



 Author: Trust-Worthy
    
    
"""
import subprocess
import pyshark
import platform
from scapy.all import *


def get_network_interfaces() -> list:

    interfaces: list = get_if_list()
    
    return interfaces
