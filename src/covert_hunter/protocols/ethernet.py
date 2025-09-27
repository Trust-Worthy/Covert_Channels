# covert_hunter/protocols/ethernet.py

from datetime import datetime
import time
from covert_hunter.core.parser import Packet_Parser


class EthernetFrame:
    """_summary_
    Ethernet Frame class for extracting layer 2 ethernet data.
    """
    packet_counter: int = 0
    packet_ids = set()
    @classmethod
    def generate_unique_packet_id(cls) -> int:
        cls.packet_counter += 1
        now = time.time_ns() # ~ 19 digits
        
        # shift counter into lower digits
        return now * 1_000_000 + cls.packet_counter
    
    def __init__(self, timestamp: datetime = None, all_bytes: bytes = None, parser: Packet_Parser = None):
        
        self._timestamp: datetime | None = None
        self._destination_mac: bytes | None = None
        self._source_mac: bytes | None  = None
        self._ethernet_type: bytes | None = None
        self._packet_id: int | None = None
        
        # Optionally parse if data was passed in
        if all_bytes is not None and timestamp is not None:
            self.parse_ethernet_frame(timestamp, all_bytes)
        
    def parse_ethernet_frame(cls, self, timestamp:datetime, all_bytes: bytes) -> TypeError:
        
        self.check_bytes(all_bytes=all_bytes)
        
        self.timestamp = timestamp
        self.destination_mac = all_bytes[0:6]
        self.source_mac = all_bytes[6:12]
        self.ethernet_type = all_bytes[12:14]
        self.packet_id = cls.generate_unique_packet_id()
        
    def check_bytes(self, all_bytes: bytes) -> bool:
        if not isinstance(all_bytes, bytes):
                raise TypeError("Incoming packet data is not of type bytes.")
        if len(all_bytes) < 14:  # Ethernet frame header is 14 bytes
            raise ValueError("Ethernet frame is too short.")
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
        
        
    @property
    def packet_id(self) -> int:
        return self._packet_id
    
    @packet_id.setter
    def packet_id(cls, self, id: int):
        if not isinstance(id, int):
            raise TypeError("Packet ID should be of type int")
        
        if id in cls.packet_ids:
            raise ValueError(f"{id} already assigned")
        