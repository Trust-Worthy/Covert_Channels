
from cleaning_captures.packet_parser import Packet_parser

from typing import Union, Optional
from cleaning_captures.packet_parser import Packet_parser

class QUIC_HEADER:
    """
    Simple QUIC header class that parses and stores the contents of an initial QUIC packet header.
    
    Args:
        Packet_parser (_type_): Used to track parsing state and metadata across protocols.
    """

    def __init__(self, all_bytes: bytes, parser: Packet_parser):
        self._parser: Packet_parser = parser
        self._parser.packet_type = type(self)

        # Long or Short header?
        self._is_long_header: bool = bool(all_bytes[0] & 0x80)

        # Common fields
        self._first_byte: int = all_bytes[0]
        self._version: Optional[bytes] = None
        self._dcid_length: Optional[int] = None
        self._scid_length: Optional[int] = None
        self._dcid: Optional[bytes] = None
        self._scid: Optional[bytes] = None

        # Next Protocol Placeholder
        self._next_protocol: Optional[None] = None  # Placeholder for future protocol chaining

        self.parse_quic_header(all_bytes)
        remaining_bytes: bytearray = self.get_remaining_bytes_after_header(all_bytes)

        if not self._parser.check_if_finished_parsing():
            self.create_next_protocol(remaining_bytes, self._parser)

    def parse_quic_header(self, all_bytes: bytes) -> None:
        offset = 1  # Already read the first byte

        if self._is_long_header:
            self._version = all_bytes[offset:offset+4]
            offset += 4

            self._dcid_length = all_bytes[offset]
            offset += 1
            self._dcid = all_bytes[offset:offset + self._dcid_length]
            offset += self._dcid_length

            self._scid_length = all_bytes[offset]
            offset += 1
            self._scid = all_bytes[offset:offset + self._scid_length]
            offset += self._scid_length

            # Note: This example assumes an Initial packet with crypto payload next (can be extended for other long types)

        else:
            # Short header (DCID implied, no version, less parsing here)
            self._dcid = all_bytes[1:9]  # Example: 8-byte DCID
            offset = 9

        self._parser.store_and_track_bytes(offset)

    def get_remaining_bytes_after_header(self, all_bytes: bytes) -> bytearray:
        if self._parser.check_if_finished_parsing():
            return all_bytes[self._parser.offset_pointer:]
        else:
            raise ValueError("Incomplete or invalid QUIC header")

    def create_next_protocol(self, remaining_bytes: bytearray, parser: Packet_parser):
        # Placeholder - depends on payload (e.g., CRYPTO, STREAM, etc.)
        self._next_protocol = None
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
    def next_protocol(self):
        return self._next_protocol

    @property
    def parser(self):
        return self._parser


if __name__ == "__main__":
    # Dummy for testing
    example_bytes = b'\xc0\x00\x00\x00\x01\x08\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\x08\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8'
    dummy_parser = Packet_parser()
    quic_header = QUIC_HEADER(example_bytes, dummy_parser)

    
