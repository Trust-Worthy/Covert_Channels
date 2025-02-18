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


'''

import numpy as np
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Any


### TO-DO ###
# add error handling to TLS functions if necessary so that nothing breaks
# ADD separate sub classe for arp request, arp reply, icmp request, icmp reply
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

class Packet_parser:
    def __init__(self, raw_data: bytes):
        self._offset_pointer: int = 0
        self._total_bytes_read: int = 0
        self._packet_data_bytes: bytearray  # Full packet data in bytes
        self._packet_data_np_arr: np.ndarray  # Full packet data as a NumPy array
        self._finished_parsing: bool ### flag needs to be set when the last nested protocol is finished being parsed


    def store_and_track_bytes(self, raw_bytes: bytes, field: Any) -> None:
        """
        Updates byte_pointer, total_bytes_read, and appends the bytes to the packet data bytes.

         When the byte_pointer is moved, update...
        
        1) The byte_pointer
        2) The total_bytes_read
        3)

        Args:
            raw_bytes (bytes): The bytes being tracked
            field (Any): The field to which the bytes will be assigned
        """
    


       

        field = raw_bytes ### Setting some protocol field to the bytes being tracked
        self.move_byte_pointer += raw_bytes ### Moving byte pointer to the next offset
        self.total_bytes_read += raw_bytes
        self.packet_data_bytes.append(bytes)


    '''
    so i'm doing += in this method but under the hood it's really doing += correct? Can I do += and it still be fine just so it's easier to read
    and I don't get freaked out that the byte pointer is being overwritten.
    
    '''

    def create_np_array_from_bytes(self) -> np.ndarray:
        self.packet_data_np_arr = np.frombuffer(self.packet_data_bytes,dtype=np.uint8)

        return self.packet_data_np_arr

    @property
    def offset_pointer(self) -> int:
        return self._offset_pointer
    
    @offset_pointer.setter
    def move_byte_pointer(self,value: bytes) -> None:
        
        self._offset_pointer += len(value)


    @property
    def total_bytes_read(self)-> int:
        return self._total_bytes_read
    
    @total_bytes_read.setter
    def total_bytes_read(self,value:int) -> None:
        self._total_bytes_read += value

    
    @property
    def packet_data_bytes(self) -> bytearray:
        return self._packet_data_bytes
    
    @packet_data_bytes.setter
    def packet_data_bytes(self, value:bytes) -> None:
        self._packet_data_bytes.append(value)

    @property
    def packet_data_np_arr(self) -> np.ndarray:
        return self._packet_data_np_arr


class Ethernet_Packet:


    def __init__(self, raw_bytes: bytes):
        
        self._destination_mac: bytes  # Offset: Bytes 0-5 (6 bytes)
        self._source_mac: bytes  # Offset: Bytes 6-11 (6 bytes)
        self._ethernet_type: bytes  # Offset: Bytes 12-13 (2 bytes)
        self._timestamp: datetime  # Timestamp of packet capture
        self._parser: Parser = Parser()


        self._parse_ethernet_frame(raw_bytes)

    def _parse_ethernet_frame(self,raw_bytes:bytes, parser: Parser)-> None:

        self._destination_mac = raw_bytes[0:6]
        parser.byte_pointer = 



    

    def from_bytes(cls, data: bytes, timestamp: datetime) -> "Ethernet_Packet":
        return cls(
            destination_mac=data[0:6],
            source_mac=data[6:12],
            ethernet_type=data[12:14],
            timestamp=timestamp,
            packet_data_byte=data,
            packet_data_np_arr=np.frombuffer(data, dtype=np.uint8)
        )

    # Getter and setter for destination_mac
    @property
    def destination_mac(self) -> bytes:
        return self._destination_mac

    @destination_mac.setter
    def destination_mac(self, value: bytes):
        if len(value) != 6:
            raise ValueError("MAC address must be 6 bytes long")
        self._destination_mac = value

    # Getter and setter for source_mac
    @property
    def source_mac(self) -> bytes:
        return self._source_mac

    @source_mac.setter
    def source_mac(self, value: bytes):
        if len(value) != 6:
            raise ValueError("MAC address must be 6 bytes long")
        self._source_mac = value

    # Getter and setter for ethernet_type
    @property
    def ethernet_type(self) -> bytes:
        return self._ethernet_type

    @ethernet_type.setter
    def ethernet_type(self, value: bytes):
        if len(value) != 2:
            raise ValueError("Ethernet type must be 2 bytes long")
        self._ethernet_type = value

    # Getter for timestamp (no setter needed, as it's set on initialization)
    @property
    def timestamp(self) -> datetime:
        return self._timestamp

    # Getter and setter for parser (if needed)
    @property
    def parser(self) -> 'Parser':  # Assuming Parser is a class
        return self._parser

    @parser.setter
    def parser(self, value: 'Parser'):
        if not isinstance(value, Parser):
            raise ValueError("parser must be an instance of the Parser class")
        self._parser = value


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
    def __init__(self,raw_bytes: bytes):

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

class TLS_Packet(TCP_Packet):


    def __init__():
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

    

   
    def from_bytes(cls, data: bytes) -> "TLS_Packet":
        tls_packet = cls(
            packet_data_byte=data,
            packet_data_np_arr=np.frombuffer(data, dtype=np.uint8)
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
    operation_code: bytes  # Bytes 20-21: Operation (2 bytes) ### ARP REquest or ARP Reply
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
class ARP_REQUEST(ARP):
    pass

@dataclass
class ARP_REPLY(ARP):
    pass

@dataclass
class ICMP_REQUEST:
    pass

@dataclass
class ICMP_REPLY:
    pass

@dataclass
class HTTP_Packet(TCP_Packet):
    def __init__(self, raw_data: bytes):
        super.__init__()


        self.is_request: Optional[bool] = None  # True if request, False if response
        self.method: Optional[bytes] = None  # Only for requests
        self.request_uri: Optional[bytes] = None  # Only for requests
        self.http_version: Optional[bytes] = None  # In both requests and responses
        
        self.status_code: Optional[bytes] = None  # Only for responses
        self.status_message: Optional[bytes] = None  # Only for responses
        
        self.headers: Dict[bytes, bytes] = {}  # Headers dictionary
        self.body: Optional[bytes] = None  # Optional body
        
        self.parse(raw_data)  # Parse the raw HTTP data when an instance is created

    def parse(self, raw_data: bytes):
        # Separate headers and body
        header_section, body_section = raw_data.split(b"\r\n\r\n", 1) if b"\r\n\r\n" in raw_data else (raw_data, b"")
        
        # Split headers into lines
        header_lines = header_section.split(b"\r\n")
        
        if not header_lines:
            return
        
        # Split the first line (Request-Line or Status-Line)
        first_line_parts = header_lines[0].split(b" ")
        
        if first_line_parts[0].startswith(b"HTTP/"):
            # This is a response
            self.is_request = False
            self.http_version = first_line_parts[0]  # e.g., HTTP/1.1
            self.status_code = first_line_parts[1]  # e.g., 200
            self.status_message = b" ".join(first_line_parts[2:])  # e.g., OK
        else:
            # This is a request
            self.is_request = True
            self.method = first_line_parts[0]  # e.g., GET
            self.request_uri = first_line_parts[1]  # e.g., /index.html
            self.http_version = first_line_parts[2]  # e.g., HTTP/1.1
        
        # Parse headers
        for line in header_lines[1:]:
            if b": " in line:
                key, value = line.split(b": ", 1)
                self.headers[key] = value
        
        # Store body
        self.body = body_section

@dataclass
class DNS:
    pass

@dataclass
class QUIC:
    pass


@dataclass
class OTHER:
    pass


'''
arp request 
arp reply
icmp request 
icmp reply
dns 
http
tls
quic
other 

'''