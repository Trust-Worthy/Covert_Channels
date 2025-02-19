from ethernet import Ethernet_Frame
from packet_parser import Packet_parser

class IP_Header(Ethernet_Frame):
    """
    Simple IP header class that parses and stores the contents.

    Args:
        Ethernet_Frame (_type_): Ip header inherits ethernet frame becasue of the structure of the TCP/IP model.
    """

    def __init__(self, timestamp_data, raw_bytes):
        super().__init__(timestamp_data, raw_bytes)



        self._version: bytes = self._raw_bytes[0:1] >> 4  # 4 bits for version
        self._diff_service_field: bytes = self._raw_bytes[1:2]  # 1 byte
        self._total_length: bytes = self._raw_bytes[2:4]  # 2 bytes
        self._identification: bytes = self._raw_bytes[4:6]  # 2 bytes
        self._flags: bytes = self._raw_bytes[6:8]  # 2 bytes
        self._ttl: bytes = self._raw_bytes[8:9]  # 1 byte
        self._protocol: bytes = self._raw_bytes[9:10]  # 1 byte
        self._header_checksum: bytes = self._raw_bytes[10:12]  # 2 bytes
        self._source_address: bytes = self._raw_bytes[12:16]  # 4 bytes
        self._dst_address: bytes = self._raw_bytes[16:20]  # 4 bytes
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