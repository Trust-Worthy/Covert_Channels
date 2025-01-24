'''
@Author Trust-Worthy

'''

import numpy as np
from dataclasses import dataclass


@dataclass
class Packet:
    destination_mac: bytearray # Offset: Bytes 1-6. Destination MAC is the first 6 bytes
    source_mac: bytearray # Offset: Bytes 7-12. Source MAC is the second set of 6 bytes
    ethernet_type: bytearray # Offset: Bytes 13-14. This is 2 bytes and it indicates the type of data in the payload of the ethernet frame



@dataclass
class DHCP:



@dataclass
class TCP:


@dataclass
class TLS


@dataclass
class ARP

@dataclass
class ICMP

@dataclass
class OTHER