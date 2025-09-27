# covert_hunter/protocols/ethernet.py

from datetime import datetime

class EthernetFrame:
    """_summary_
    
    Ethernet Frame class for extracting layer 2 ethernet data.
    """
    def __init__(self, timestamp: datetime, all_bytes:bytes):
        
        self._timestamp: datetime = timestamp
        self._destination_mac: bytes = None
        self._source_mac: bytes = None
        
        
        
    @property
    def destination_mac(self) -> bytes:
        return self._destination_mac
    
    @property
    def source_mac(self) -> bytes:
        return self._source_mac