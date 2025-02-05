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

### TO-DO ###
# What is the maximum size that a packet can be?
# Create a get_packet_size_func


@dataclass
class Ethernet_Packet:
    destination_mac: bytes # Offset: Bytes 1-6. Destination MAC is the first 6 bytes
    source_mac: bytes # Offset: Bytes 7-12. Source MAC is the second set of 6 bytes
    ethernet_type: bytes # Offset: Bytes 13-14. This is 2 bytes and it indicates the type of data in the payload of the ethernet frame
    timestamp: datetime # Date and time when the packet was captured
    packet_data_byte: bytes # All data from the capture in a bytes
    packet_data_np: np.array # All data from the capture in a numpy array

@dataclass
class TCP_Packet(Ethernet_Packet):
    version: bytes # byte 15
    diff_service_field: bytes # byte 16 in the packet
    total_length: bytes # byte 17 & byte 18 in the packet
    identification: bytes # byte 19 & 20
    flags: bytes # byte 21 and 22
    ttl: bytes # byte 23
    protocol: bytes # byte 24 --> should be "TCP" What are the different codes for different types of packets?
    header_checksum: bytes # byte 25 & 26
    source_address: bytes # 27 - 30 bytes --> ip address 
    dst_address: bytes # 31 - 34 bytes --> ip address
    source_port: bytes  # 35 - 36 bytes offset --> source port
    dst_port: bytes # 37 - 38 byte offset --> destination port
    sequence_number: bytes # 39 - 42 byte offset (4 bytes in total)
    ack_number: bytes # 43 - 46 byte offset (4 bytes in total)
    header_length: bytes # 47 byte offset (1 byte in total)
    ack_flags: bytes # 48 - 49 byte offset (2 bytes)
    window: bytes # 51 - 52 byte offset (2 bytes)
    checksum: bytes # 53 - 54 byte offset (2 bytes)
    urgent_pointer: bytes # 55 - 56 (2 bytes)
    options: bytes # 57 - 68 ( 12 bytes)
    # options are: NOP, NOP, Timestamps, 
@dataclass
class TCP_Packet(Ethernet_Packet):
    version: bytes  # byte 15 (IP header) --> IP version (4 bits for IPv4 or IPv6)
    diff_service_field: bytes  # byte 16 (IP header) --> Differentiated Services Field (DS Field) in the IP header
    total_length: bytes  # byte 17 & byte 18 (IP header) --> Total length of the packet (IP header + data)
    identification: bytes  # byte 19 & 20 (IP header) --> Identification field (used for fragmentation)
    flags: bytes  # byte 21 & 22 (IP header) --> Flags field in the IP header
    ttl: bytes  # byte 23 (IP header) --> Time-to-Live field (used to prevent infinite loops)
    protocol: bytes  # byte 24 (IP header) --> Protocol field specifies the next layer protocol (TCP in this case)
    header_checksum: bytes  # byte 25 & 26 (IP header) --> Checksum for the IP header
    source_address: bytes  # 27 - 30 bytes (IP header) --> Source IP address
    dst_address: bytes  # 31 - 34 bytes (IP header) --> Destination IP address
    source_port: bytes  # 35 - 36 bytes (TCP portion) --> Source port number in the TCP header
    dst_port: bytes  # 37 - 38 bytes (TCP portion) --> Destination port number in the TCP header
    sequence_number: bytes  # 39 - 42 bytes (TCP portion) --> Sequence number (4 bytes in total) in the TCP header
    ack_number: bytes  # 43 - 46 bytes (TCP portion) --> Acknowledgment number (4 bytes in total) in the TCP header
    header_length: bytes  # 47 bytes (TCP portion) --> Data offset (the length of the TCP header)
    ack_flags: bytes  # 48 - 49 bytes (TCP portion) --> Acknowledgment flags (2 bytes in the TCP header)
    window: bytes  # 51 - 52 bytes (TCP portion) --> Window size for flow control (2 bytes in the TCP header)
    checksum: bytes  # 53 - 54 bytes (TCP portion) --> TCP checksum (error checking for TCP data)
    urgent_pointer: bytes  # 55 - 56 bytes (TCP portion) --> Urgent pointer (points to urgent data, 2 bytes in TCP header)
    options: bytes  # 57 - 68 bytes (TCP portion) --> Options field (12 bytes, may include NOP, timestamp, etc.)
    # options are: NOP, NOP, Timestamps, segment size, window scale factor, etc





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