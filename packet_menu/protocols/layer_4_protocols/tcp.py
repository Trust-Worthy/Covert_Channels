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

    
    def 