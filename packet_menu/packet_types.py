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
from typing import Optional


### TO-DO ###
# add error handling to TLS functions if necessary so that nothing breaks
# What is the maximum size that a packet can be?
# Verify that all the fields for the class method are correct! Chatgpt is buggy as a mug
# Add class method for all classes missing them!
# Create a get_packet_size_func
# Create functions in my clean.py for each class or create them in thie file. Basically... WAIT. I don't need 
### Next prompt ###
'''


So essentially I need to create getters for every protocol?

So let's say that I'm parsing bytes from a txt file that I captured packets using tcpdump. 

Would I declare an instance of ethernet? stop at the proper byte offset for ethernet. Then create the ip header class and call the getter for the ethernet class?
'''



@dataclass
class Ethernet_Packet:
    destination_mac: bytes  # Offset: Bytes 0-5 (6 bytes)
    source_mac: bytes  # Offset: Bytes 6-11 (6 bytes)
    ethernet_type: bytes  # Offset: Bytes 12-13 (2 bytes)
    timestamp: datetime  # Timestamp of packet capture
    packet_data_byte: bytes  # Full packet data in bytes
    packet_data_np: np.array  # Full packet data as a NumPy array

    @classmethod
    def from_bytes(cls, data: bytes, timestamp: datetime) -> "Ethernet_Packet":
        return cls(
            destination_mac=data[0:6],
            source_mac=data[6:12],
            ethernet_type=data[12:14],
            timestamp=timestamp,
            packet_data_byte=data,
            packet_data_np=np.frombuffer(data, dtype=np.uint8)
        )

@dataclass
class IP_Header(Ethernet_Packet):
    version: bytes  # Offset: Byte 0 (4 bits for version)
    diff_service_field: bytes  # Offset: Byte 1 (1 byte)
    total_length: bytes  # Offset: Bytes 2-3 (2 bytes)
    identification: bytes  # Offset: Bytes 4-5 (2 bytes)
    flags: bytes  # Offset: Bytes 6-7 (2 bytes)
    ttl: bytes  # Offset: Byte 8 (1 byte)
    protocol: bytes  # Offset: Byte 9 (1 byte)
    header_checksum: bytes  # Offset: Bytes 10-11 (2 bytes)
    source_address: bytes  # Offset: Bytes 12-15 (4 bytes)
    dst_address: bytes  # Offset: Bytes 16-19 (4 bytes)

@dataclass
class TCP_Packet(IP_Header):
    source_port: bytes  # Offset: Bytes 20-21 (2 bytes)
    dst_port: bytes  # Offset: Bytes 22-23 (2 bytes)
    sequence_number: bytes  # Offset: Bytes 24-27 (4 bytes)
    ack_number: bytes  # Offset: Bytes 28-31 (4 bytes)
    header_length: bytes  # Offset: Byte 32 (4 bits for data offset)
    flags: bytes  # Offset: Byte 33 (1 byte, includes flags)
    window: bytes  # Offset: Bytes 34-35 (2 bytes)
    checksum: bytes  # Offset: Bytes 36-37 (2 bytes)
    urgent_pointer: bytes  # Offset: Bytes 38-39 (2 bytes)
    options: bytes  # Offset: Bytes 40-51 (12 bytes, optional)

@dataclass
class UDP(IP_Header):
    source_port: bytes  # Bytes 0-1 (2 bytes): Source Port
    destination_port: bytes  # Bytes 2-3 (2 bytes): Destination Port
    length: bytes  # Bytes 4-5 (2 bytes): Length of UDP header + payload
    checksum: bytes  # Bytes 6-7 (2 bytes): Checksum (optional, used for integrity verification)
    payload: bytes  # Bytes 8+: UDP Payload (e.g., DHCP, DNS, etc.)

    @classmethod
    def from_bytes(cls, packet_data: bytes) -> "UDP":
        """
        Parses a UDP packet from raw bytes.
        :param packet_data: Raw UDP packet bytes
        :return: Parsed UDP dataclass object
        """
        if len(packet_data) < 8:
            raise ValueError("UDP header must be at least 8 bytes long.")

        return cls(
            source_port=packet_data[0:2],  # 2 bytes
            destination_port=packet_data[2:4],  # 2 bytes
            length=packet_data[4:6],  # 2 bytes
            checksum=packet_data[6:8],  # 2 bytes
            payload=packet_data[8:],  # Everything after 8 bytes is payload
        )

@dataclass
class TLS_Packet(TCP_Packet):
    tls_record_data: Optional[bytes] = None
    handshake_type: Optional[bytes] = None  # Offset: Byte 5 (1 byte)
    handshake_length: Optional[bytes] = None  # Offset: Bytes 6-9 (4 bytes)
    
    client_hello_version: Optional[bytes] = None  # Offset: Bytes 10-11 (2 bytes, TLS 1.2 only)
    random_bytes: Optional[bytes] = None  # Offset: Bytes 12-43 (32 bytes, TLS 1.2 only)
    session_id_length: Optional[bytes] = None  # Offset: Byte 44 (1 byte, TLS 1.2 only)
    session_id: Optional[bytes] = None
    cipher_suites_length: Optional[bytes] = None
    cipher_suites: Optional[bytes] = None
    compression_methods_length: Optional[bytes] = None
    compression_methods: Optional[bytes] = None
    extensions_length: Optional[bytes] = None
    extensions: Optional[bytes] = None
    
    tls_13_record_data: Optional[bytes] = None
    encrypted_application_data: Optional[bytes] = None

    @classmethod
    def from_bytes(cls, data: bytes) -> "TLS_Packet":
        tls_packet = cls(
            packet_data_byte=data,
            packet_data_np=np.frombuffer(data, dtype=np.uint8)
        )
        tls_packet.parse_tls(data)
        return tls_packet

    def parse_tls(self, data: bytes):
        if data[0:1] == b'\x16' and data[1:2] == b'\x03':
            version = data[1:3]
            if version == b'\x03\x03':  # TLS 1.2
                self._parse_tls_1_2(data)
            elif version == b'\x03\x04':  # TLS 1.3
                self._parse_tls_1_3(data)

    def _parse_tls_1_2(self, data: bytes):
        self.client_hello_version = data[10:12]
        self.random_bytes = data[12:44]
        self.session_id_length = data[44:45]
        session_id_len = int.from_bytes(self.session_id_length, 'big')
        self.session_id = data[45:45 + session_id_len]
        offset = 45 + session_id_len
        self.cipher_suites_length = data[offset:offset + 2]
        cipher_suites_len = int.from_bytes(self.cipher_suites_length, 'big')
        self.cipher_suites = data[offset + 2:offset + 2 + cipher_suites_len]
        offset += 2 + cipher_suites_len
        self.compression_methods_length = data[offset:offset + 1]
        comp_methods_len = int.from_bytes(self.compression_methods_length, 'big')
        self.compression_methods = data[offset + 1:offset + 1 + comp_methods_len]
        offset += 1 + comp_methods_len
        self.extensions_length = data[offset:offset + 2]
        ext_len = int.from_bytes(self.extensions_length, 'big')
        self.extensions = data[offset + 2:offset + 2 + ext_len]

    def _parse_tls_1_3(self, data: bytes):
        self.tls_13_record_data = data[5:]  # Capture full record data for TLS 1.3
        self.encrypted_application_data = data[5:]  # Since everything after handshake is encrypted

@dataclass
class ARP(Ethernet_Packet):
    hardware_type: bytes  # Bytes 14-15: Hardware type (2 bytes)
    protocol_type: bytes  # Bytes 16-17: Protocol type (2 bytes)
    hardware_address_length: bytes  # Byte 18: Hardware address length (1 byte)
    protocol_address_length: bytes  # Byte 19: Protocol address length (1 byte)
    operation_code: bytes  # Bytes 20-21: Operation (2 bytes)
    sender_hardware_address: bytes  # Bytes 22-27: Sender MAC address (6 bytes)
    sender_protocol_address: bytes  # Bytes 28-31: Sender IP address (4 bytes)
    target_hardware_address: bytes  # Bytes 32-37: Target MAC address (6 bytes)
    target_protocol_address: bytes  # Bytes 38-41: Target IP address (4 bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ARP":
        if len(data) < 28:
            raise ValueError("Insufficient data for ARP packet")
        return cls(
            destination_mac=data[0:6],
            source_mac=data[6:12],
            ethernet_type=data[12:14],
            hardware_type=data[14:16],
            protocol_type=data[16:18],
            hardware_address_length=data[18:19],
            protocol_address_length=data[19:20],
            operation_code=data[20:22],
            sender_hardware_address=data[22:28],
            sender_protocol_address=data[28:32],
            target_hardware_address=data[32:38],
            target_protocol_address=data[38:42],
            timestamp=datetime.now(),
            packet_data_byte=data,
            packet_data_np=np.frombuffer(data, dtype=np.uint8),
        )

@dataclass
class DHCP(UDP):
    # DHCP packet fields (from DHCPv4 standard)
    operation_code_bytes: bytes  # Byte 0: Operation code (1 byte)
    hardware_type_bytes: bytes  # Byte 1: Hardware type (1 byte)
    hardware_address_length_bytes: bytes  # Byte 2: Hardware address length (1 byte)
    hops_bytes: bytes  # Byte 3: Hops (1 byte)
    transaction_id_bytes: bytes  # Bytes 4-7: Transaction ID (4 bytes)
    seconds_elapsed_bytes: bytes  # Bytes 8-9: Seconds elapsed (2 bytes)
    flags_bytes: bytes  # Bytes 10-11: Flags (2 bytes)
    client_ip_address_bytes: bytes  # Bytes 12-15: Client IP address (4 bytes)
    your_ip_address_bytes: bytes  # Bytes 16-19: Your (client) IP address (4 bytes)
    server_ip_address_bytes: bytes  # Bytes 20-23: Server IP address (4 bytes)
    gateway_ip_address_bytes: bytes  # Bytes 24-27: Gateway IP address (4 bytes)
    client_hardware_address_bytes: bytes  # Bytes 28-43: Client hardware address (16 bytes)
    server_host_name_bytes: bytes  # Bytes 44-107: Server host name (64 bytes)
    boot_file_name_bytes: bytes  # Bytes 108-171: Boot file name (128 bytes)
    dhcp_options_bytes: bytes  # Bytes 172+: DHCP options (variable length)

    @classmethod
    def from_bytes(cls, packet_data: bytes) -> "DHCP":
        """
        Parses a DHCP packet from raw bytes.
        :param packet_data: Raw DHCP packet bytes
        :return: Parsed DHCP dataclass object
        """
        if len(packet_data) < 240:
            raise ValueError("DHCP packet must be at least 240 bytes long.")


        # Call parent class to handle Ethernet header parsing
        ethernet_packet = Ethernet_Packet.from_bytes(packet_data)
        
        # Call parent class to handle IP header parsing (after Ethernet)
        ip_packet = IP_Header.from_bytes(ethernet_packet.payload_bytes)
        
        # Call parent class to handle UDP header parsing (after IP)
        udp_packet = UDP.from_bytes(ip_packet.payload_bytes)

        # Parse DHCP-specific fields from the payload (after UDP header)
        dhcp_payload = udp_packet.payload_bytes

        return cls(
            operation_code_bytes=packet_data[0:1],  # 1 byte: Operation code
            hardware_type_bytes=packet_data[1:2],  # 1 byte: Hardware type
            hardware_address_length_bytes=packet_data[2:3],  # 1 byte: Hardware address length
            hops_bytes=packet_data[3:4],  # 1 byte: Hops
            transaction_id_bytes=packet_data[4:8],  # 4 bytes: Transaction ID
            seconds_elapsed_bytes=packet_data[8:10],  # 2 bytes: Seconds elapsed
            flags_bytes=packet_data[10:12],  # 2 bytes: Flags
            client_ip_address_bytes=packet_data[12:16],  # 4 bytes: Client IP address
            your_ip_address_bytes=packet_data[16:20],  # 4 bytes: Your IP address
            server_ip_address_bytes=packet_data[20:24],  # 4 bytes: Server IP address
            gateway_ip_address_bytes=packet_data[24:28],  # 4 bytes: Gateway IP address
            client_hardware_address_bytes=packet_data[28:44],  # 16 bytes: Client hardware address
            server_host_name_bytes=packet_data[44:108],  # 64 bytes: Server host name
            boot_file_name_bytes=packet_data[108:172],  # 128 bytes: Boot file name
            dhcp_options_bytes=packet_data[172:],  # Variable length: DHCP options
        )



@dataclass
class DNS:





@dataclass
class ICMP

@dataclass
class OTHER


'''
arp request 
arp reply
icmp request 
icmp reply
dns 
https
tls
quic

'''