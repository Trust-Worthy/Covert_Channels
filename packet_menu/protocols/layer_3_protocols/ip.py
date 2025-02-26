from typing import Optional



from cleaning_captures.packet_parser import Packet_parser
from


class IP_Header():
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

        self._parser: Packet_parser = parser
        self._version: bytes = remaining_bytes[0:1] >> 4  # 4 bits for version
        self._diff_service_field: bytes = remaining_bytes[1:2]  # 1 byte
        self._total_length: bytes = remaining_bytes[2:4]  # 2 bytes
        self._identification: bytes = remaining_bytes[4:6]  # 2 bytes
        self._flags: bytes = remaining_bytes[6:8]  # 2 bytes
        self._ttl: bytes = remaining_bytes[8:9]  # 1 byte
        self._protocol: bytes = remaining_bytes[9:10]  # 1 byte
        self._header_checksum: bytes = remaining_bytes[10:12]  # 2 bytes
        self._source_address: bytes = remaining_bytes[12:16]  # 4 bytes
        self._dst_address: bytes = remaining_bytes[16:20]  # 4 bytes
    


    def parse_ip_header(self, remaining_bytes: bytearray, parser: Packet_parser) -> None:

    def create_next_protocol(self, remaining_bytes: bytearray) -> Optional[]
    ### TO-DO ###
    # write logic that decides what protocol is created next based off of the next bytes.
    ### first call parse_ip_header
    ### remember, I create next protocol after I call get_remaining_bytes_after_ip_header
        pass
    def get_remaining_bytes_after_ip_header(self, remaining_bytes: bytearray,) -> bytearray:
        pass