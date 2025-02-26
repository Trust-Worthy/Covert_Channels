

class IP_Header():
    """
    Simple IP header class that parses and stores the contents.

    Args:
        Ethernet_Frame (_type_): Ip header inherits ethernet frame becasue of the structure of the TCP/IP model.
    """

    def __init__(self, raw_bytes):
        """
        Initializing all fields for an Ip header.

        Args:
            raw_bytes (_type_): Remaining bytes to be processed.
        """


        self._version: bytes = raw_bytes[0:1] >> 4  # 4 bits for version
        self._diff_service_field: bytes = raw_bytes[1:2]  # 1 byte
        self._total_length: bytes = raw_bytes[2:4]  # 2 bytes
        self._identification: bytes = raw_bytes[4:6]  # 2 bytes
        self._flags: bytes = raw_bytes[6:8]  # 2 bytes
        self._ttl: bytes = raw_bytes[8:9]  # 1 byte
        self._protocol: bytes = raw_bytes[9:10]  # 1 byte
        self._header_checksum: bytes = raw_bytes[10:12]  # 2 bytes
        self._source_address: bytes = raw_bytes[12:16]  # 4 bytes
        self._dst_address: bytes = raw_bytes[16:20]  # 4 bytes
   