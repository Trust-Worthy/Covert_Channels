from cleaning_captures.packet_parser import Packet_parser



class TCP_SEGMENT():
    def __init__(self,all_bytes: bytes, parser: Packet_parser):

        self._parser: Packet_parser = parser
        self._parser.packet_type = type(self)

        self._source_port: bytes  # Offset: Bytes 20-21 (2 bytes)
        self._dst_port: bytes  # Offset: Bytes 22-23 (2 bytes)
        self._sequence_number: bytes  # Offset: Bytes 24-27 (4 bytes)
        self._ack_number: bytes  # Offset: Bytes 28-31 (4 bytes)
        self._header_length: bytes  # Offset: Byte 32 (4 bits for data offset)
        self._flags: bytes  # Offset: Byte 33 (1 byte, includes flags)
        self.window_size: bytes  # Offset: Bytes 34-35 (2 bytes)
        self._checksum: bytes  # Offset: Bytes 36-37 (2 bytes)
        self._urgent_pointer: bytes  # Offset: Bytes 38-39 (2 bytes)
        self._options: bytes  # Offset: Bytes 40-51 (12 bytes, optional)

    
    def parse_tcp_segment(self, all_bytes: bytes) -> None:
        pass

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
