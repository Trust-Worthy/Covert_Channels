# covert_hunter/protocols/ethernet.py

from datetime import datetime
from covert_hunter.core.parser import Packet_Parser


class EthernetFrame:
    """_summary_
    
    Ethernet Frame class for extracting layer 2 ethernet data.
    """
    def __init__(self, timestamp: datetime, all_bytes:bytes, parser: Packet_Parser = None):
        
        self._timestamp: datetime = timestamp
        self._destination_mac: bytes = None
        self._source_mac: bytes = None
        
        
        
    def parse_ethernet_frame(self, all_bytes: bytes) -> None:
        
        self.destination_mac = all_bytes[0:6]
        self.source_mac
        
        
    @property
    def destination_mac(self) -> bytes:
        return self._destination_mac
    
    @destination_mac.setter
    def destination_mac(self, data: bytes):
        
        if len(data) != 6:
            raise ValueError("Destination MAC address must be 6 bytes long")
        
        self._destination_mac = data
    
    @property
    def source_mac(self) -> bytes:
        return self._source_mac
    
    @source_mac.setter
    def source_mac(self, data: bytes):
        
        if len(data) != 6:
            raise ValueError("Source MAC address must be 6 bytes long")
        
        self.source_mac = data
    