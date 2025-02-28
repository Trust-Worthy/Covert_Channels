

from application_layer.quic import QUIC_PACKET
from cleaning_captures.packet_parser import Packet_parser

class UDP_HEADER():


    def __init__(self, all_bytes: bytearray, parser: Packet_parser):
        
        self._parser = parser
        self._protocol_type = type(self)

        self._source_port: bytes  # Bytes 0-1 (2 bytes): Source Port
        self._destination_port: bytes  # Bytes 2-3 (2 bytes): Destination Port
        self._length: bytes  # Bytes 4-5 (2 bytes): Length of UDP header + payload
        self._checksum: bytes  # Bytes 6-7 (2 bytes): Checksum (optional, used for integrity verification)
        self._payload: bytes  # Bytes 8+: UDP Payload (e.g., DHCP, DNS, etc.)

   
    def parse_udp_header(self, all_bytes: bytearray) -> None:

        self._source_port = all_bytes[:2]
        self._destination_port = all_bytes[2:4]
        self._length = all_bytes[4:6]
        self._checksum = all_bytes[6:8]
        self._payload = all_bytes[8:]

        offset: int = 8 ### UDP is always 8 bytes

        self._parser.store_and_track_bytes(offset)

    def get_remaining_bytes_after_ip_header(self, all_bytes:bytearray) -> bytearray:

        if self._parser.check_if_finished_parsing():
            remaining_bytes: bytearray = all_bytes[self._parser.offset_pointer:]
            return remaining_bytes
        else:
            ### TO-DO log termination here (use logging)
            raise ValueError("Error: Incomplete or invalid IP header")


    @property
    def source_port(self) -> bytes:
        return self._source_port
    
    @source_port.setter
    def source_port(self, value: bytes) -> None:
        self._source_port = value

    @property
    def destination_port(self) -> bytes:
        return self._destination_port
    
    @destination_port.setter
    def destination_port(self, value: bytes) -> None:
        self._destination_port = value

    @property
    def length(self) -> bytes:
        return self._length
    
    @length.setter
    def length(self, value: bytes) -> None:
        self._length = value

    @property
    def checksum(self) -> bytes:
        return self._checksum
    
    @checksum.setter
    def checksum(self, value: bytes) -> None:
        self._checksum = value

    @property
    def payload(self) -> bytes:
        return self._payload
    
    @payload.setter
    def payload(self, value: bytes) -> None:
        self._payload = value