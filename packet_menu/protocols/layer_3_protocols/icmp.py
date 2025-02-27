
from cleaning_captures.packet_parser import Packet_parser
from datetime import datetime
from typing import Optional, Union

class ICMP_MESSAGE():
    

    def __init__(self, all_bytes: bytearray, parser: Packet_parser):

        self._parser: Packet_parser = parser

        self._type: bytes             # 1 byte (ICMP Type, e.g., 0x08 for Echo Request)
        self._code: bytes             # 1 byte (ICMP Code, typically 0x00 for Echo Request/Reply)
        self._checksum: bytes         # 2 bytes (ICMP Checksum)
        self._identifier: bytes       # 2 bytes (Identifier for matching Request/Reply)
        self._sequence_num: bytes     # 2 bytes (Sequence Number for distinguishing requests)
        self._data: bytes = None      # Data field (for echo data or padding)
        self._is_request: bool
        self._timestamp: int = None


    
    def parse_icmp_message(self, all_bytes: bytearray) -> None:

        # Logic to determine if it's a request or reply
        self._type = all_bytes[0]
        if self._type == 0x08:  # Echo Request
            self._is_request = True
        elif self._type == 0x00:  # Echo Reply
            self._is_request = False
        else:
            raise ValueError("Unsupported ICMP Type")
        
        self._code = all_bytes[1]
        self._checksum = all_bytes[2:4]
        self._identifier = all_bytes[4:6]
        self._sequence_num = all_bytes[6:8]

        if len(all_bytes) > 8:

            self._timestamp = int.from_bytes(all_bytes[8:12], byteorder='big')
            self._data = all_bytes[12:]


    # Getters and Setters for the fields
    
    @property
    def type(self) -> bytes:
        return self._type
    
    @type.setter
    def type(self, value: bytes):
        self._type = value
    
    @property
    def code(self) -> bytes:
        return self._code
    
    @code.setter
    def code(self, value: bytes):
        self._code = value

    @property
    def checksum(self) -> bytes:
        return self._checksum
    
    @checksum.setter
    def checksum(self, value: bytes):
        self._checksum = value

    @property
    def identifier(self) -> bytes:
        return self._identifier
    
    @identifier.setter
    def identifier(self, value: bytes):
        self._identifier = value

    @property
    def sequence_num(self) -> bytes:
        return self._sequence_num
    
    @sequence_num.setter
    def sequence_num(self, value: bytes):
        self._sequence_num = value

    @property
    def data(self) -> bytes:
        return self._data
    
    @data.setter
    def data(self, value: bytes):
        self._data = value

    @property
    def timestamp(self) -> Optional[datetime]:
        return self._timestamp
    
    @timestamp.setter
    def timestamp(self, value: Optional[datetime]):
        self._timestamp = value
        
    # Getter for parser, no setter
    @property
    def parser(self) -> Packet_parser:
        return self._parser