
from cleaning_captures.packet_parser import Packet_parser


class ARP_PACKET():



        def __init__(self, all_bytes: bytearray, parser: Packet_parser):

            self._hardware_type: bytes  # Bytes 14-15: Hardware type (2 bytes)
            self._protocol_type: bytes  # Bytes 16-17: Protocol type (2 bytes)
            self._hardware_size: bytes  # Byte 18: Hardware address length (1 byte)
            self._protocol_size: bytes  # Byte 19: Protocol address length (1 byte)
            self._operation_code: bytes  # Bytes 20-21: Operation (2 bytes) ### ARP REquest or ARP Reply
            self._sender_mac_address: bytes  # Bytes 22-27: Sender MAC address (6 bytes)
            self._sender_ip_address: bytes  # Bytes 28-31: Sender IP address (4 bytes)
            self._target_mac_address: bytes  # Bytes 32-37: Target MAC address (6 bytes)
            self._target_ip_address: bytes  # Bytes 38-41: Target IP address (4 bytes)




        def parse_arp_packet(self, all_bytes: bytearray)



            # Getters and Setters for all fields
        
        @property
        def hardware_type(self) -> bytes:
            return self._hardware_type
        
        @hardware_type.setter
        def hardware_type(self, value: bytes):
            self._hardware_type = value

        @property
        def protocol_type(self) -> bytes:
            return self._protocol_type
        
        @protocol_type.setter
        def protocol_type(self, value: bytes):
            self._protocol_type = value

        @property
        def hardware_size(self) -> bytes:
            return self._hardware_size
        
        @hardware_size.setter
        def hardware_size(self, value: bytes):
            self._hardware_size = value

        @property
        def protocol_size(self) -> bytes:
            return self._protocol_size
        
        @protocol_size.setter
        def protocol_size(self, value: bytes):
            self._protocol_size = value

        @property
        def operation_code(self) -> bytes:
            return self._operation_code
        
        @operation_code.setter
        def operation_code(self, value: bytes):
            self._operation_code = value

        @property
        def sender_mac_address(self) -> bytes:
            return self._sender_mac_address
        
        @sender_mac_address.setter
        def sender_mac_address(self, value: bytes):
            self._sender_mac_address = value

        @property
        def sender_ip_address(self) -> bytes:
            return self._sender_ip_address
        
        @sender_ip_address.setter
        def sender_ip_address(self, value: bytes):
            self._sender_ip_address = value

        @property
        def target_mac_address(self) -> bytes:
            return self._target_mac_address
        
        @target_mac_address.setter
        def target_mac_address(self, value: bytes):
            self._target_mac_address = value

        @property
        def target_ip_address(self) -> bytes:
            return self._target_ip_address
        
        @target_ip_address.setter
        def target_ip_address(self, value: bytes):
            self._target_ip_address = value

        # Getter for parser (no setter)

        @property
        def parser(self) -> Packet_parser:
            return self._parser



    

