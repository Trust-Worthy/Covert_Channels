'''
@Author Trust-Worthy

Why am I creating these classes?
- For easy packet statistics
- For clean preparation of the data for

Why is it important to have all of the respective fields for the different types of classes?


functions that I need

byte array to integer 
byte array to numpy array unit8
unit8 to byte array


next prompt:
I need some feedback on my code     

'''



import numpy as np
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Ethernet_Packet:
    destination_mac: bytearray # Offset: Bytes 1-6. Destination MAC is the first 6 bytes
    source_mac: bytearray # Offset: Bytes 7-12. Source MAC is the second set of 6 bytes
    ethernet_type: bytearray # Offset: Bytes 13-14. This is 2 bytes and it indicates the type of data in the payload of the ethernet frame
    timestamp: datetime # Date and time when the packet was captured
    packet_data_byte: bytearray # All data from the capture in a bytearray
    packet_data_np: np.array # All data from the capture in a numpy array

@dataclass
class TCP_Packet(Ethernet_Packet):
    # All the byte 
    version: bytearray # byte 15
    diff_service_field: bytearray # byte 16 in the packet
    total_length: bytearray # byte 17 & byte 18 in the packet
    identification: bytearray # byte 19 & 20
    flags: bytearray # byte 21 and 22
    ttl: bytearray # byte 23
    protocol: bytearray # byte 24 --> should be "TCP" What are the different codes for different types of packets?
    header_checksum: bytearray # byte 25 & 26
    source_address: bytearray # 27 - 30 bytes --> ip address 
    dst_address: bytearray # 31 - 34 bytes --> ip address
    source_port: bytearray  # 35 - 36 bytes offset --> source port
    dst_port: bytearray # 37 - 38 byte offset --> destination port



@dataclass
class DHCP:

@dataclass
class DNS:


@dataclass
class TLS


@dataclass
class ARP

@dataclass
class ICMP

@dataclass
class OTHER