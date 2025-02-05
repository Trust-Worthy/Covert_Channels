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
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


### TO-DO ###
# What is the maximum size that a packet can be?
# Create a get_packet_size_func


@dataclass
class Ethernet_Packet:
    # Maximum size of 1518 bytes
    destination_mac: bytes # Offset: Bytes 1-6. Destination MAC is the first 6 bytes
    source_mac: bytes # Offset: Bytes 7-12. Source MAC is the second set of 6 bytes
    ethernet_type: bytes # Offset: Bytes 13-14. This is 2 bytes and it indicates the type of data in the payload of the ethernet frame
    timestamp: datetime # Date and time when the packet was captured
    packet_data_byte: bytes # All data from the capture in a bytes
    packet_data_np: np.array # All data from the capture in a numpy array

@dataclass
class IP_Header(Ethernet_Packet):
    # Maximum size of ipv4 64kb or 65,535 bytes similar for ipv6
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


@dataclass
class TCP_Packet(IP_Header):
    
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
class TLS_Packet(TCP_Packet):
    # General fields for any TLS record
    tls_record_data: Optional[bytes] = None  # Raw TLS record data; this is the full byte stream representing the packet
    handshake_type: Optional[bytes] = None  # Type of the handshake message. 1 byte (Offset: 6)
    handshake_length: Optional[bytes] = None  # Length of the handshake message. 4 bytes (Offset: 7-10)

    # TLS 1.2 specific handshake fields
    client_hello_version: Optional[bytes] = None  # Version of the TLS client hello message. 2 bytes (Offset: 11-12)
    random_bytes: Optional[bytes] = None  # Random bytes sent by the client. 32 bytes (Offset: 13-46)
    session_id_length: Optional[bytes] = None  # Length of session ID. 1 byte (Offset: 47)
    session_id: Optional[bytes] = None  # The session ID sent by the client. Size varies (Offset: 48-48 + session_id_length)
    cipher_suites_length: Optional[bytes] = None  # Length of cipher suites list. 2 bytes (Offset: varies)
    cipher_suites: Optional[bytes] = None  # List of cipher suites supported by the client. Size varies (Offset: varies)
    compression_methods_length: Optional[bytes] = None  # Length of compression methods list. 1 byte (Offset: varies)
    compression_methods: Optional[bytes] = None  # List of compression methods supported. Size varies (Offset: varies)
    extensions_length: Optional[bytes] = None  # Length of extensions list. 2 bytes (Offset: varies)
    extensions: Optional[bytes] = None  # List of extensions in the client hello. Size varies (Offset: varies)
    
    # TLS 1.3 specific fields (handshake or record layer)
    tls_13_record_data: Optional[bytes] = None  # For TLS 1.3, the whole record is treated as a block of data
    encrypted_application_data: Optional[bytes] = None  # Raw encrypted data in the application record

    def initialize_tls_fields(self, tls_message_type: str, packet_data: bytes):
        """
        Initializes the TLS packet fields based on the message type and packet data.
        This function can handle both TLS 1.2 and TLS 1.3 packets.
        
        :param tls_message_type: The type of the TLS message (e.g., 'handshake', 'application_data')
        :param packet_data: The raw bytes of the packet data to be parsed and extracted
        """
        if tls_message_type == 'application_data':
            # If the message type is application data, we set the encrypted_application_data
            self.encrypted_application_data = packet_data
            self.tls_record_data = None  # Clear handshake-related fields if it's application data
        elif tls_message_type == 'handshake':
            # Handle handshake records for both TLS 1.2 and 1.3
            self.handshake_type = packet_data[5:6]  # 1 byte for handshake type at offset 6
            self.handshake_length = packet_data[6:10]  # 4 bytes for handshake length at offset 7-10

            # Check if TLS 1.2 or TLS 1.3 (we'll assume version-related fields can indicate this)
            if packet_data[0:1] == b'\x16' and packet_data[1:2] == b'\x03':  # Record type and version byte for TLS
                version = packet_data[1:3]
                if version == b'\x03\x03':  # TLS 1.2
                    self._parse_tls_1_2_handshake(packet_data)
                elif version == b'\x03\x04':  # TLS 1.3 (TLS 1.3 starts with this version)
                    self._parse_tls_1_3_handshake(packet_data)
                else:
                    # Handle any other TLS version if needed
                    pass
            else:
                # Handle any non-handshake type records if needed
                pass
        else:
            # Handle any other types of TLS records (e.g., alerts, change cipher spec, etc.)
            pass
    
    def _parse_tls_1_2_handshake(self, packet_data: bytes):
        """ Helper function to parse TLS 1.2 handshake specific fields """
        
        # Parsing ClientHello message fields in TLS 1.2
        self.client_hello_version = packet_data[11:13]  # 2 bytes for version at offset 11-12
        self.random_bytes = packet_data[13:45]  # 32 bytes for random at offset 13-46
        self.session_id_length = packet_data[47:48]  # 1 byte for session ID length at offset 47
        
        # Unpacking session_id_length using struct to interpret the byte
        session_id_length_value = struct.unpack('B', self.session_id_length)[0]  # 1 byte, gives the length of session_id
        self.session_id = packet_data[48:48 + session_id_length_value]  # Session ID field: Varies based on length

        # Cipher suites length (2 bytes) and the cipher suites list (varies in size)
        cipher_suites_length_offset = 48 + session_id_length_value
        self.cipher_suites_length = packet_data[cipher_suites_length_offset:cipher_suites_length_offset + 2]  # 2 bytes
        cipher_suites_offset = cipher_suites_length_offset + 2
        cipher_suites_length_value = struct.unpack('>H', self.cipher_suites_length)[0]  # 2 bytes, gives the number of cipher suites
        self.cipher_suites = packet_data[cipher_suites_offset:cipher_suites_offset + cipher_suites_length_value]  # Varies in size

        # Compression methods (1 byte length followed by a list of supported methods)
        compression_methods_length_offset = cipher_suites_offset + cipher_suites_length_value
        self.compression_methods_length = packet_data[compression_methods_length_offset:compression_methods_length_offset + 1]  # 1 byte
        compression_methods_offset = compression_methods_length_offset + 1
        compression_methods_length_value = struct.unpack('B', self.compression_methods_length)[0]  # 1 byte, gives the length of compression methods
        self.compression_methods = packet_data[compression_methods_offset:compression_methods_offset + compression_methods_length_value]  # Varies in size

        # Extensions (2-byte length followed by extension data)
        extensions_length_offset = compression_methods_offset + compression_methods_length_value
        self.extensions_length = packet_data[extensions_length_offset:extensions_length_offset + 2]  # 2 bytes for extensions length
        extensions_offset = extensions_length_offset + 2
        extensions_length_value = struct.unpack('>H', self.extensions_length)[0]  # 2 bytes, gives the length of extensions
        self.extensions = packet_data[extensions_offset:extensions_offset + extensions_length_value]  # Varies in size

    def _parse_tls_1_3_handshake(self, packet_data: bytes):
        """ Helper function to parse TLS 1.3 handshake specific fields """
        
        # TLS 1.3 handshake parsing is more simplified in this example
        # For TLS 1.3, the record is just parsed as a block of data.
        self.tls_13_record_data = packet_data[5:]  # In TLS 1.3, we simply take the remaining data starting at byte 5
        # More detailed parsing of TLS 1.3 can be added depending on the specific handshake structure (e.g., ClientHello, ServerHello, etc.)


'''
# Example function that creates a TCP_Packet object
def create_tcp_packet_from_bytes(packet_data: bytes) -> TCP_Packet:
    # Extracting different fields from the raw packet data (as an example)
    destination_mac = packet_data[:6]
    source_mac = packet_data[6:12]
    ethernet_type = packet_data[12:14]
    version = packet_data[14:15]
    diff_service_field = packet_data[15:16]
    total_length = packet_data[16:18]
    identification = packet_data[18:20]
    flags = packet_data[20:22]
    ttl = packet_data[22:23]
    protocol = packet_data[23:24]
    header_checksum = packet_data[24:26]
    source_address = packet_data[26:30]
    dst_address = packet_data[30:34]
    source_port = packet_data[34:36]
    dst_port = packet_data[36:38]
    sequence_number = packet_data[38:42]
    ack_number = packet_data[42:46]
    header_length = packet_data[46:47]
    ack_flags = packet_data[47:49]
    window = packet_data[49:51]
    checksum = packet_data[51:53]
    urgent_pointer = packet_data[53:55]
    options = packet_data[55:67]

    # Create the TCP_Packet object
    return TCP_Packet(
        destination_mac=destination_mac,
        source_mac=source_mac,
        ethernet_type=ethernet_type,
        timestamp=datetime.now(),  # Just an example timestamp
        packet_data_byte=packet_data,
        packet_data_np=np.array(packet_data),
        version=version,
        diff_service_field=diff_service_field,
        total_length=total_length,
        identification=identification,
        flags=flags,
        ttl=ttl,
        protocol=protocol,
        header_checksum=header_checksum,
        source_address=source_address,
        dst_address=dst_address,
        source_port=source_port,
        dst_port=dst_port,
        sequence_number=sequence_number,
        ack_number=ack_number,
        header_length=header_length,
        ack_flags=ack_flags,
        window=window,
        checksum=checksum,
        urgent_pointer=urgent_pointer,
        options=options
    )

'''

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