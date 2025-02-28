from cleaning_captures.packet_parser import Packet_parser



class TCP_HEADER():
    def __init__(self,all_bytes: bytes, parser: Packet_parser):

        self._parser: Packet_parser = parser
        self._parser.packet_type = type(self)

        self._source_port: bytes  # Offset: Bytes 20-21 (2 bytes)
        self._dst_port: bytes  # Offset: Bytes 22-23 (2 bytes)
        self._sequence_number: bytes  # Offset: Bytes 24-27 (4 bytes)
        self._ack_number: bytes  # Offset: Bytes 28-31 (4 bytes)
        self._header_length: bytes  # Offset: Byte 32 (4 bits for data offset)
        self._reserved_bits: bytes
        self._flags: bytes  # Offset: Byte 33 (1 byte, includes flags)
        self._window_size: bytes  # Offset: Bytes 34-35 (2 bytes)
        self._checksum: bytes  # Offset: Bytes 36-37 (2 bytes)
        self._urgent_pointer: bytes  # Offset: Bytes 38-39 (2 bytes)
        self._options: bytes  # Offset: Bytes 40-51 (12 bytes, optional)

        
    
    def parse_tcp_header(self, all_bytes: bytes) -> None:

        self._source_port = all_bytes[0:2]
        self._dst_port = all_bytes[2:4]
        self._sequence_number = all_bytes[4:8]
        self._ack_number = all_bytes[8:12]
        self._header_length = (all_bytes[12] >> 4) & 0x0F 
        self._reserved_bits = all_bytes[12] & 0x0F
        self._flags = all_bytes[13]
        self._window_size = all_bytes[14:16]
        self._checksum = all_bytes[16:18]
        self._urgent_pointer = all_bytes[18:20]

        offset: int = 20

        # Calculate options based on header length
        header_length_bytes = self._header_length * 4  # Convert 4-bit value to bytes
        if header_length_bytes > 20:  # If options are present
            self._options = all_bytes[20:header_length_bytes]
            offset = header_length_bytes
        else:
            self._options = None  # No options present

        self._parser.store_and_track_bytes(offset)
    def get_remaining_bytes_after_tcp_header(self, all_bytes: bytearray) -> bytearray:

        if self._parser.check_if_finished_parsing():
            remaining_bytes: bytearray = all_bytes[self._parser.offset_pointer:]
            return remaining_bytes
        else:
            ### TO-DO log termination here (use logging)
            raise ValueError("Error: Incomplete or invalid TCP header")


    def extract_tcp_flags(self) -> dict[str,bytes]:
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

        flag_dict = {
            "FIN": self._flags & 0x01,
            "SYN": (self._flags & 0x02) >> 1,
            "RST": (self._flags & 0x04) >> 2,
            "PSH": (self._flags & 0x08) >> 3,
            "ACK": (self._flags & 0x10) >> 4,
            "URG": (self._flags & 0x20) >> 5,
            "ECE": (self._flags & 0x40) >> 6,
            "CWR": (self._flags & 0x80) >> 7
        }


        return flag_dict

# Getters and Setters for all fields
    
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
        return self.window_size
    
    @window_size.setter
    def window_size(self, value: bytes):
        self.window_size = value

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
