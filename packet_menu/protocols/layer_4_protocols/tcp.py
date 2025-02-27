


@dataclass
class TCP_SEGMENT(IP_Header):
    def __init__(self,all_bytes: bytes):

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