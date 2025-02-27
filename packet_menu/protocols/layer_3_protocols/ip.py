from typing import Optional, Union



from cleaning_captures.packet_parser import Packet_parser
from layer_4_protocols.tcp import TCP_SEGMENT
from layer_4_protocols.udp import UDP_DATAGRAM


class IP_HEADER():
    """
    Simple IP header class that parses and stores the contents.

    Args:
        Ethernet_Frame (_type_): Ip header inherits ethernet frame becasue of the structure of the TCP/IP model.
    """

    def __init__(self, remaining_bytes: bytearray, parser: Packet_parser):
        """
        Initializing all fields for an Ip header.

        Args:
            remaining_bytes (_type_): Remaining bytes to be processed.
        """
        ## Pass on the parser to the next protocol
        self._parser: Packet_parser = parser
        self._version: bytes 
        self._diff_service_field: bytes 
        self._total_length: bytes  
        self._identification: bytes 
        self._flags: bytes
        self._ttl: bytes
        self._protocol_type: bytes 
        self._header_checksum: bytes 
        self._source_address: bytes 
        self._dst_address: bytes
    


    def parse_ip_header(self, remaining_bytes: bytearray) -> None:
        
        
        self._version: bytes = remaining_bytes[0:1] >> 4  # 4 bits for version
        self._diff_service_field: bytes = remaining_bytes[1:2]  # 1 byte
        self._total_length: bytes = remaining_bytes[2:4]  # 2 bytes
        self._identification: bytes = remaining_bytes[4:6]  # 2 bytes
        self._flags: bytes = remaining_bytes[6:8]  # 2 bytes
        self._ttl: bytes = remaining_bytes[8:9]  # 1 byte
        self._protocol_type: bytes = remaining_bytes[9:10]  # 1 byte
        self._header_checksum: bytes = remaining_bytes[10:12]  # 2 bytes
        self._source_address: bytes = remaining_bytes[12:16]  # 4 bytes
        self._dst_address: bytes = remaining_bytes[16:20]  # 4 bytes

    def create_next_protocol(self, remaining_bytes: bytearray) -> Union[TCP_SEGMENT, UDP_DATAGRAM]:
    ### TO-DO ###
    # write logic that decides what protocol is created next based off of the next bytes.
    ### first call parse_ip_header
    ### remember, I create next protocol after I call get_remaining_bytes_after_ip_header
        
        if self.protocol_type == 0x01: ### ICMP 
            pass
        elif self.protocol_type == 0x06: ### TCP
            pass
        elif self.protocol_type == 0x11: ### UDP
            pass
        else:
            self.

    
    
    def get_remaining_bytes_after_ip_header(self, remaining_bytes: bytearray,) -> bytearray:
        pass


    @property
    def parser(self):
        return self._parser

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value: bytes):
        self._version = value

    @property
    def diff_service_field(self):
        return self._diff_service_field

    @diff_service_field.setter
    def diff_service_field(self, value: bytes):
        self._diff_service_field = value

    @property
    def total_length(self):
        return self._total_length

    @total_length.setter
    def total_length(self, value: bytes):
        self._total_length = value

    @property
    def identification(self):
        return self._identification

    @identification.setter
    def identification(self, value: bytes):
        self._identification = value

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, value: bytes):
        self._flags = value

    @property
    def ttl(self):
        return self._ttl

    @ttl.setter
    def ttl(self, value: bytes):
        self._ttl = value

    @property
    def protocol_type(self):
        return self.__protocol_type

    @protocol_type.setter
    def protocol_type(self, value: bytes):
        self._protocol_type = value

    @property
    def header_checksum(self):
        return self._header_checksum

    @header_checksum.setter
    def header_checksum(self, value: bytes):
        self._header_checksum = value

    @property
    def source_address(self):
        return self._source_address

    @source_address.setter
    def source_address(self, value: bytes):
        self._source_address = value

    @property
    def dst_address(self):
        return self._dst_address

    @dst_address.setter
    def dst_address(self, value: bytes):
        self._dst_address = value