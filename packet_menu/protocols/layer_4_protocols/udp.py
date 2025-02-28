

from application_layer.quic import QUIC

@dataclass
class UDP_DATAGRAM(IP_Header):
    source_port: bytes  # Bytes 0-1 (2 bytes): Source Port
    destination_port: bytes  # Bytes 2-3 (2 bytes): Destination Port
    length: bytes  # Bytes 4-5 (2 bytes): Length of UDP header + payload
    checksum: bytes  # Bytes 6-7 (2 bytes): Checksum (optional, used for integrity verification)
    payload: bytes  # Bytes 8+: UDP Payload (e.g., DHCP, DNS, etc.)

    @classmethod
    def from_bytes(cls, packet_data: bytes) -> "UDP":
        """
        Parses a UDP packet from raw bytes.
        :param packet_data: Raw UDP packet bytes
        :return: Parsed UDP dataclass object
        """
        if len(packet_data) < 8:
            raise ValueError("UDP header must be at least 8 bytes long.")

        return cls(
            source_port=packet_data[0:2],  # 2 bytes
            destination_port=packet_data[2:4],  # 2 bytes
            length=packet_data[4:6],  # 2 bytes
            checksum=packet_data[6:8],  # 2 bytes
            payload=packet_data[8:],  # Everything after 8 bytes is payload
        )