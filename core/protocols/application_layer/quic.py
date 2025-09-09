
from typing import Optional



class QUIC_HEADER:
    """
    Detailed QUIC header class that parses and stores the contents of an Initial/Handshake/0-RTT/Retry QUIC packet.
    
    Args:
        Packet_parser (_type_): Used to track parsing state and metadata across protocols.
    """

    def __init__(self, all_bytes: bytes, parser: Packet_parser):
        self._parser: Packet_parser = parser
        self._parser.packet_type = type(self)

        # Header type
        self._is_long_header: bool = bool(all_bytes[0] & 0x80)
        self._first_byte: int = all_bytes[0]

        # Common fields
        self._version: Optional[bytes] = None
        self._dcid_length: Optional[int] = None
        self._scid_length: Optional[int] = None
        self._dcid: Optional[bytes] = None
        self._scid: Optional[bytes] = None

        # Long header-specific
        self._packet_type_str: Optional[str] = None
        self._token_length: Optional[int] = None
        self._token: Optional[bytes] = None
        self._length: Optional[int] = None
        self._packet_number: Optional[bytes] = None
        self._payload: Optional[bytes] = None
        self._retry_token: Optional[bytes] = None
        self._retry_integrity_tag: Optional[bytes] = None

        self._next_protocol: Optional[None] = None  # Placeholder for future protocol chaining

        self.parse_quic_header(all_bytes)
        remaining_bytes: bytearray = self.get_remaining_bytes_after_header(all_bytes)

        if not self._parser.check_if_finished_parsing():
            self.create_next_protocol(remaining_bytes, self._parser)

    def parse_quic_header(self, all_bytes: bytes) -> None:
        offset = 1  # Already read the first byte

        if self._is_long_header:
            self._version = all_bytes[offset:offset + 4]
            version_int = int.from_bytes(self._version, 'big')
            offset += 4

            self._packet_type_str = get_packet_type_str(self._first_byte & 0x30 >> 4)

            self._dcid_length = all_bytes[offset]
            offset += 1
            self._dcid = all_bytes[offset:offset + self._dcid_length]
            offset += self._dcid_length

            self._scid_length = all_bytes[offset]
            offset += 1
            self._scid = all_bytes[offset:offset + self._scid_length]
            offset += self._scid_length

            if self._packet_type_str == "Initial":
                self._token_length, varint_len = self.parse_varint(all_bytes[offset:])
                offset += varint_len

                self._token = all_bytes[offset:offset + self._token_length]
                offset += self._token_length

                self._length, varint_len = self.parse_varint(all_bytes[offset:])
                offset += varint_len

                pn_length = (self._first_byte & 0x03) + 1
                self._packet_number = all_bytes[offset:offset + pn_length]
                offset += pn_length

                self._payload = all_bytes[offset:offset + self._length - pn_length]
                offset += len(self._payload)

            elif self._packet_type_str == "0-RTT" or self._packet_type_str == "Handshake":
                self._length, varint_len = self.parse_varint(all_bytes[offset:])
                offset += varint_len

                pn_length = (self._first_byte & 0x03) + 1
                self._packet_number = all_bytes[offset:offset + pn_length]
                offset += pn_length

                self._payload = all_bytes[offset:offset + self._length - pn_length]
                offset += len(self._payload)

            elif self._packet_type_str == "Retry":
                # Retry format: everything after SCID is retry_token + integrity tag (last 16 bytes)
                retry_end = len(all_bytes) - 16
                self._retry_token = all_bytes[offset:retry_end]
                self._retry_integrity_tag = all_bytes[retry_end:]
                offset = len(all_bytes)

        else:
            # Short header (DCID assumed to be known)
            self._dcid = all_bytes[1:9]  # Example assumption
            offset = 9

        self._parser.store_and_track_bytes(offset)

    def parse_varint(self, data: bytes) -> tuple[int, int]:
        """Parse QUIC variable-length integer and return (value, length in bytes)."""
        first_byte = data[0]
        if first_byte < 0x40:
            return first_byte, 1
        elif first_byte < 0x80:
            return ((first_byte & 0x3F) << 8 | data[1]), 2
        elif first_byte < 0xC0:
            return ((first_byte & 0x3F) << 24 |
                    data[1] << 16 |
                    data[2] << 8 |
                    data[3]), 4
        else:
            return ((first_byte & 0x3F) << 56 |
                    data[1] << 48 |
                    data[2] << 40 |
                    data[3] << 32 |
                    data[4] << 24 |
                    data[5] << 16 |
                    data[6] << 8 |
                    data[7]), 8

    def get_remaining_bytes_after_header(self, all_bytes: bytes) -> bytearray:
        if self._parser.check_if_finished_parsing():
            return all_bytes[self._parser.offset_pointer:]
        else:
            raise ValueError("Incomplete or invalid QUIC header")

    def create_next_protocol(self, remaining_bytes: bytearray, parser: Packet_parser):
        self._next_protocol = None  # Extend as needed
        return self._next_protocol

    @property
    def is_long_header(self) -> bool:
        return self._is_long_header

    @property
    def version(self) -> Optional[bytes]:
        return self._version

    @property
    def dcid(self) -> Optional[bytes]:
        return self._dcid

    @property
    def scid(self) -> Optional[bytes]:
        return self._scid

    @property
    def token_length(self) -> Optional[int]:
        return self._token_length

    @property
    def token(self) -> Optional[bytes]:
        return self._token

    @property
    def length(self) -> Optional[int]:
        return self._length

    @property
    def packet_number(self) -> Optional[bytes]:
        return self._packet_number

    @property
    def payload(self) -> Optional[bytes]:
        return self._payload

    @property
    def retry_token(self) -> Optional[bytes]:
        return self._retry_token

    @property
    def retry_integrity_tag(self) -> Optional[bytes]:
        return self._retry_integrity_tag

    @property
    def packet_type_str(self) -> Optional[str]:
        return self._packet_type_str

    @property
    def next_protocol(self):
        return self._next_protocol

    @property
    def parser(self):
        return self._parser


def get_packet_type_str(type_bits: int) -> str:
    return {
        0x00: "Initial",
        0x01: "0-RTT",
        0x02: "Handshake",
        0x03: "Retry"
    }.get(type_bits, "Unknown")


    
