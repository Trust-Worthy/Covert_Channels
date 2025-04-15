from typing import Union

from processing import Packet_parser

from application_layer import TLS_Packet, DNS, HTTP, HTTPS

from undefined_layer.undefined_protocol import OTHER_PROTOCOL

class TCP_HEADER():
    def __init__(self,all_bytes: bytes, parser: Packet_parser):

        self._parser: Packet_parser = parser
        self._parser.packet_type = type(self) ### tracks the current type of protocol that's being processed

        self._source_port: bytes  # Offset: Bytes 20-21 (2 bytes)
        self._dst_port: bytes  # Offset: Bytes 22-23 (2 bytes)
        self._sequence_number: bytes  # Offset: Bytes 24-27 (4 bytes)
        self._ack_number: bytes  # Offset: Bytes 28-31 (4 bytes)
        self._header_length: int  # Offset: Byte 32 (4 bits for data offset)
        self._reserved_bits: bytes
        self._flags: bytes  # Offset: Byte 33 (1 byte, includes flags)
        self._window_size: bytes  # Offset: Bytes 34-35 (2 bytes)
        self._checksum: bytes  # Offset: Bytes 36-37 (2 bytes)
        self._urgent_pointer: bytes  # Offset: Bytes 38-39 (2 bytes)
        self._options: bytes  # Offset: Bytes 40-51 (12 bytes, optional)

        self._next_protocol_type: bytes
        self._next_protocol: Union[TLS_Packet,DNS,HTTP,HTTPS] ### Protocols I'm choosing to capture.

        self.parse_tcp_header(all_bytes, all_bytes)
        remaining_bytes: bytearray = self.get_remaining_bytes_after_tcp_header(all_bytes)
        
        if not self._parser.check_if_finished_parsing():
            self.create_next_protocol(remaining_bytes,self._parser)

    def parse_tcp_header(self, all_bytes: bytes) -> None:

        self._source_port = all_bytes[0:2]
        self._dst_port = all_bytes[2:4]
        self._sequence_number = all_bytes[4:8]
        self._ack_number = all_bytes[8:12]
        self._header_length = (all_bytes[12] >> 4) & 0x0F 
        self._reserved_bits = (all_bytes[12] >> 1) & 0x07
        self._flags = all_bytes[13]
        self._window_size = all_bytes[14:16]
        self._checksum = all_bytes[16:18]
        self._urgent_pointer = all_bytes[18:20]

        offset: int = 20

        # Calculate options based on header length
        header_length_bytes = self._header_length
        if header_length_bytes > 20:  # If options are present
            self._options = all_bytes[20:header_length_bytes]
            offset = header_length_bytes
        else:
            self._options = b''  # No options present

        self._parser.store_and_track_bytes(offset)
    def get_remaining_bytes_after_tcp_header(self, all_bytes: bytearray) -> bytearray:

        return all_bytes[self._parser.offset_pointer:]
        


    def extract_tcp_flags(self) -> dict[str,int]:
        """
        0x01 (00000001)	FIN	Finish: Indicates the sender wants to terminate the connection.
        0x02 (00000010)	SYN	Synchronize: Used to establish a connection (TCP 3-way handshake).
        0x04 (00000100)	RST	Reset: Forces a connection reset (abrupt termination).
        0x08 (00001000)	PSH	Push: Requests immediate delivery of data.
        0x10 (00010000)	ACK	Acknowledgment: Indicates the acknowledgment number is valid.
        0x20 (00100000)	URG	Urgent: Data should be prioritized (uses the Urgent Pointer field).
        0x40 (01000000)	ECE	Explicit Congestion Notification Echo: Signals network congestion.
        0x80 (10000000)	CWR	Congestion Window Reduced: Used with ECN to reduce congestion.

        Returns:
            dict[str,bytes]: _description_
        """
        flag_names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
        return {name: (self._flags >> i) & 1 for i, name in enumerate(flag_names)}


    def create_next_protocol(self, remaining_bytes: bytearray, parser: Packet_parser) -> Union[HTTP,DNS,TLS_Packet]:

        protocol_handlers = {
            80: HTTP,
            53: DNS
        }
    

        dst_port: int = int.from_bytes(self._dst_port,byteorder='big')
        src_port: int = int.from_bytes(self._source_port,byteorder='big')

        if self.is_tls(self,remaining_bytes):
            self._next_protocol = TLS_Packet(remaining_bytes, parser)
            return self._next_protocol

        handler = protocol_handlers.get(dst_port) or protocol_handlers.get(src_port) or OTHER_PROTOCOL
        if type(handler) == DNS:
            self._next_protocol = handler(remaining_bytes,parser,True)
            return self._next_protocol
        
        self._next_protocol = handler(remaining_bytes,parser)
        return self._next_protocol
    
    def is_tls(tcp_payload: bytes) -> bool:
        if len(tcp_payload) < 3:
            return False  # Not enough bytes for TLS

        content_type = tcp_payload[0]
        version_major = tcp_payload[1]
        version_minor = tcp_payload[2]

        VALID_TLS_CONTENT_TYPES = {0x14, 0x15, 0x16, 0x17}
        VALID_TLS_VERSIONS = {0x01, 0x02, 0x03, 0x04}

        return (
            content_type in VALID_TLS_CONTENT_TYPES and
            version_major == 0x03 and
            version_minor in VALID_TLS_VERSIONS
        )

    # Getters and Setters for all fields

    @property
    def parser(self) -> Packet_parser:
        return self._parser

    @property
    def next_protocol(self) -> Union[HTTP,DNS,TLS_Packet]:
        return self._next_protocol
    
    @next_protocol.setter
    def next_protocol(self, value: Union[HTTP,DNS,TLS_Packet]):
        self._next_protocol = value    
    
    @property
    def next_protocol_type(self) -> bytes:
        return self._next_protocol_type
    
    @next_protocol_type.setter
    def next_protocol_type(self, value: bytes) -> None:
        self._next_protocol_type = value

    @property
    def source_port(self) -> bytes:
        return self._source_port
    
    @source_port.setter
    def source_port(self, value: bytes):
        self._source_port = value

    @property
    def dst_port(self) -> bytes:
        return self._dst_port
    
    @dst_port.setter
    def dst_port(self, value: bytes):
        self._dst_port = value

    @property
    def sequence_number(self) -> bytes:
        return self._sequence_number
    
    @sequence_number.setter
    def sequence_number(self, value: bytes):
        self._sequence_number = value

    @property
    def ack_number(self) -> bytes:
        return self._ack_number
    
    @ack_number.setter
    def ack_number(self, value: bytes):
        self._ack_number = value

    @property
    def header_length(self) -> bytes:
        return self._header_length
    
    @header_length.setter
    def header_length(self, value: bytes):
        self._header_length = value

    @property
    def flags(self) -> bytes:
        return self._flags
    
    @flags.setter
    def flags(self, value: bytes):
        self._flags = value

    @property
    def window_size(self) -> bytes:
        return self._window_size
    
    @window_size.setter
    def window_size(self, value: bytes):
        self._window_size = value

    @property
    def checksum(self) -> bytes:
        return self._checksum
    
    @checksum.setter
    def checksum(self, value: bytes):
        self._checksum = value

    @property
    def urgent_pointer(self) -> bytes:
        return self._urgent_pointer
    
    @urgent_pointer.setter
    def urgent_pointer(self, value: bytes):
        self._urgent_pointer = value

    @property
    def options(self) -> bytes:
        return self._options
    
    @options.setter
    def options(self, value: bytes):
        self._options = value
