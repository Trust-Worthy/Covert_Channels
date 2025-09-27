# covert_hunter/protocols/ethernet.py

from datetime import datetime
from covert_hunter.core.parser import Packet_Parser


class EthernetFrame:
    """_summary_
    Ethernet Frame class for extracting layer 2 ethernet data.
    """
    def __init__(self, timestamp: datetime, all_bytes:bytes, parser: Packet_Parser = None):
        
        self._timestamp: datetime = None
        self._destination_mac: bytes = None
        self._source_mac: bytes = None
        self._ethernet_type: bytes = None
        
        self.parse_ethernet_frame(timestamp, all_bytes)
        
   
        
    def parse_ethernet_frame(self, timestamp:datetime, all_bytes: bytes) -> TypeError:
        
        self.check_bytes(all_bytes=all_bytes)
        
        self.timestamp = timestamp
        self.destination_mac = all_bytes[0:6]
        self.source_mac = all_bytes[6:12]
        self.ethernet_type = all_bytes[12:14]
        
    def check_bytes(self, all_bytes: bytes) -> bool:
    
        if type(all_bytes) != bytes:
            raise TypeError("Incoming packet data is not of type bytes.")
        return True
        
    @property
    def timestamp(self) -> datetime:
        return self._timestamp
    
    @timestamp.setter
    def timestamp(self, date: datetime):
        
        if type(date) != datetime:
            raise TypeError("Date is not a datetime object.")
        
        self._timestamp = date
        
    @property
    def destination_mac(self) -> bytes:
        return self._destination_mac
    
    @destination_mac.setter
    def destination_mac(self, data: bytes):
        if len(data) != 6:
            raise ValueError("Destination MAC address must be 6 bytes long.")
        
        self._destination_mac = data
    
    @property
    def source_mac(self) -> bytes:
        return self._source_mac
    
    @source_mac.setter
    def source_mac(self, data: bytes):
        if len(data) != 6:
            raise ValueError("Source MAC address must be 6 bytes long")
        
        self._source_mac = data
    
    @property
    def ethernet_type(self) -> bytes:
        return self._ethernet_type
    
    @ethernet_type.setter
    def ethernet_type(self, data:bytes):
        if len(data) != 2:
            raise ValueError("Ethernet Type must be 2 bytes long")
        self._ethernet_type = data