
from layer_2_protocols.ethernet import Ethernet_Frame
@dataclass
class ARP_Packet(Ethernet_Frame):
    hardware_type: bytes  # Bytes 14-15: Hardware type (2 bytes)
    protocol_type: bytes  # Bytes 16-17: Protocol type (2 bytes)
    hardware_address_length: bytes  # Byte 18: Hardware address length (1 byte)
    protocol_address_length: bytes  # Byte 19: Protocol address length (1 byte)
    operation_code: bytes  # Bytes 20-21: Operation (2 bytes) ### ARP REquest or ARP Reply
    sender_hardware_address: bytes  # Bytes 22-27: Sender MAC address (6 bytes)
    sender_protocol_address: bytes  # Bytes 28-31: Sender IP address (4 bytes)
    target_hardware_address: bytes  # Bytes 32-37: Target MAC address (6 bytes)
    target_protocol_address: bytes  # Bytes 38-41: Target IP address (4 bytes)


    @classmethod
    def from_bytes(cls, data: bytes) -> "ARP":
        if len(data) < 28:
            raise ValueError("Insufficient data for ARP packet")
        return cls(
            destination_mac=data[0:6],
            source_mac=data[6:12],
            ethernet_type=data[12:14],
            hardware_type=data[14:16],
            protocol_type=data[16:18],
            hardware_address_length=data[18:19],
            protocol_address_length=data[19:20],
            operation_code=data[20:22],
            sender_hardware_address=data[22:28],
            sender_protocol_address=data[28:32],
            target_hardware_address=data[32:38],
            target_protocol_address=data[38:42],
            timestamp=datetime.now(),
            packet_data_byte=data,
            packet_data_np=np.frombuffer(data, dtype=np.uint8),
        )
    

@dataclass
class ARP_REQUEST(ARP):
    pass

@dataclass
class ARP_REPLY(ARP):
    pass