
from protocols.layer_2_protocols.ethernet import Ethernet_Frame
from cleaning_captures.packet_parser import Packet_parser




class OTHER_PROTOCOL:
    
    def __init__(self, all_bytes: bytearray, parser: Packet_parser):
        
        self._parser: Packet_parser = parser
        self._parser.packet_type = type(self)
        self._other_protocol_size: int = len(all_bytes)
        

    @property
    def other_protocol_size(self) -> int:
        return self.other_protocol_size
    @other_protocol_size.setter
    def other_protocol_size(self, value: int):
        self._other_protocol_size = value
