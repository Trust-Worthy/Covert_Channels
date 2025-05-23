

from typing import Union



class UDP_HEADER():


    def __init__(self, all_bytes: bytearray, parser: Packet_parser):
        
        self._parser = parser
        self._parser.packet_type = type(self)

        self._source_port: int  # Bytes 0-1 (2 bytes): Source Port
        self._destination_port: int # Bytes 2-3 (2 bytes): Destination Port
        self._length: int  # Bytes 4-5 (2 bytes): Length of UDP header + payload
        self._checksum: bytes  # Bytes 6-7 (2 bytes): Checksum (optional, used for integrity verification)
        self._payload: bytes  # Bytes 8+: UDP Payload (e.g., DHCP, DNS, etc.)

        self._next_protocol_type: bytes
        self._next_protocol: Union[QUIC_HEADER,DNS,OTHER_PROTOCOL]


        self.parse_udp_header(all_bytes)
        remaining_bytes: bytearray = self.get_remaining_bytes_after_udp_header(all_bytes)
        if not self._parser.check_if_finished_parsing():
            self.create_next_protocol(remaining_bytes,self._parser)

    def parse_udp_header(self, all_bytes: bytearray) -> None:

        self._source_port = int.from_bytes(all_bytes[:2], 'big')
        self._destination_port = int.from_bytes(all_bytes[2:4],'big')
        self._length = int.from_bytes(all_bytes[4:6],'big')
        self._checksum = all_bytes[6:8]
        self._payload = all_bytes[8:]

        offset: int = 8 ### UDP is always 8 bytes

         # Ensure the packet length matches the header field
        expected_length = int.from_bytes(self._length, "big")
        if expected_length != len(all_bytes):
            raise ValueError(f"Error: UDP length mismatch! Expected {expected_length}, but got {len(all_bytes)}")

        self._parser.store_and_track_bytes(offset)

    def get_remaining_bytes_after_udp_header(self, all_bytes:bytearray) -> bytearray:

        
        remaining_bytes: bytearray = all_bytes[self._parser.offset_pointer:]
        if not remaining_bytes: 
            raise ValueError("Error: No remaining bytes after UDP header")
        
        return remaining_bytes
          
    
    def create_next_protocol(self, remaining_bytes: bytearray, parser: Packet_parser) -> Union[DNS,QUIC_HEADER,OTHER_PROTOCOL]:

        protocol_handlers = {
            54:DNS,
            443:QUIC_HEADER ### Port 443 like TLS but over UDP
        }


        dst_port: int = int.from_bytes(self._destination_port,byteorder='big')
        src_port: int = int.from_bytes(self._source_port,byteorder='big')

        if dst_port == 443 and self.is_quic(remaining_bytes):
            self._next_protocol = QUIC_HEADER(remaining_bytes, parser)
            return self._next_protocol
        else:
            handler = protocol_handlers.get(dst_port) or protocol_handlers.get(src_port) or OTHER_PROTOCOL

            if type(handler) == DNS:
                self._next_protocol = handler(remaining_bytes,parser,False)
                return self._next_protocol


        handler = protocol_handlers.get(dst_port) or protocol_handlers.get(src_port) or OTHER_PROTOCOL
        self._next_protocol = handler(remaining_bytes,parser)

        return self._next_protocol

    def is_quic(self, remaining_bytes: bytearray) -> bool:
        return remaining_bytes and remaining_bytes[0] >= 0xC0  # First byte in QUIC packets

    @property
    def source_port(self) -> int:
        return self._source_port
    
    @source_port.setter
    def source_port(self, value: int) -> None:
        self._source_port = value

    @property
    def destination_port(self) -> int:
        return self._destination_port
    
    @destination_port.setter
    def destination_port(self, value: int) -> None:
        self._destination_port = value

    @property
    def length(self) -> int:
        return self._length
    
    @length.setter
    def length(self, value: int) -> None:
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