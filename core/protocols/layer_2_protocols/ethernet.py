'''
@Author Trust-Worthy

'''


from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Union
import time

from core.processing.parser import Packet_parser



class Ethernet_Frame:
    """
    Simple Ethernet Frame class for tracking the ethernet frame data.
    """
    def __init__(self, timestamp_data: str, all_bytes: bytes):
        """
        Ethernet Frame initialization function.

        Args:
            timestamp_data (str): This is the timestamp data from when the packet was captured.
            all_bytes (bytes): All the bytes from the packet capture in hex format following the timestamp in the capture file.
        """
        self._packet_id: int # way to identify the specific packet
        self._destination_mac: bytes  # Offset: Bytes 0-5 (6 bytes)
        self._source_mac: bytes  # Offset: Bytes 6-11 (6 bytes)
        self._ethernet_type: bytes  # Offset: Bytes 12-13 (2 bytes)
        
        self._timestamp: datetime  # Timestamp of packet capture is ONLY captured in the ethernet portion.
        
        self._parser: Packet_parser = Packet_parser()
        self._parser._packet_type = type(self)

        self.parse_str_to_datetime_obj(timestamp_data)
        
        self.parse_ethernet_frame(all_bytes,self.parser)
        remaining_bytes: bytearray = self.get_remaining_bytes_after_ethernet_frame(all_bytes)
        if not self.parser.check_if_finished_parsing:
            self.create_next_protocol(remaining_bytes,self.parser)
            
        # self._next_protocol: Union[IP_HEADER,ARP_PACKET,OTHER_PROTOCOL] = None


    def parse_str_to_datetime_obj(self, timestamp_data:str) -> None:
        """
        Gets the timestamp data from the first line of the txt file and initializes the timestamp field
        in the Ethernet Frame class.

        Args:
            timestamp_data (str): timestamp data from tcpdump.
        """

        self._timestamp = datetime.strptime(timestamp_data, "%H:%M:%S.%f")


    def parse_ethernet_frame(self,all_bytes:bytes)-> None:
        """
        Specific function to place all the bytes via the correct offset into their respective fields.

        Args:
            all_bytes (bytes): hex byte data containing ALL packet information. This must be parsed to get the packet information specific
            to the ethernet framee. 
            parser (Packet_parser): is used to track the offset using its offset "pointer".
        """
        self._packet_id = self.generate_unique_packet_id()
        self._destination_mac = all_bytes[0:6] ### Set field first! This a very important step.
        self._source_mac = all_bytes[6:12]
        self._ethernet_type = all_bytes[12:14]

        offset: int = len(self.destination_mac + self.source_mac + self.ethernet_type)
        self.parser.store_and_track_bytes(offset,all_bytes=all_bytes,is_eth=True) ### Update pointer, bytes read, and store ALL the bytes in the entire packet


    def get_remaining_bytes_after_ethernet_frame(self, all_bytes:bytes) -> bytearray:
        
        if self.parser.check_if_finished_parsing and (self.parser.total_bytes_read == 14): ### if True
            
            ### If there are more bytes left
            remaining_bytes: bytearray = all_bytes[self.parser.offset_pointer:]
            return remaining_bytes
        else:
            ### TO-DO log termination here
            raise ValueError("Error: Incomplete or invalid IP header")
    # def create_next_protocol(self, remaining_bytes: bytes, parser:Packet_parser) -> Union[IP_HEADER,ARP_PACKET,OTHER_PROTOCOL]:
        
    #     ### TO-DO ###
    #     # Write code that makes decision whether to create an ip, icmp, or arp based on they next bytes!!!!

    #     if self.ethernet_type == 0x0800:
    #         self._other_protocol = IP_HEADER(remaining_bytes, parser)
    #     elif self.ethernet_type == 0x0806:
    #         self._other_protocol = ARP_PACKET(remaining_bytes, parser)
    #     else:
    #         self.other_protocol = OTHER_PROTOCOL(remaining_bytes,parser)


    def generate_unique_packet_id() -> int:
            # Get the current timestamp in seconds
        timestamp = int(time.time())
        
        # Use modulo to ensure it is an 8-digit number
        packet_id = timestamp % 100000000  # 8 digits

        return packet_id
    

    # Getter and setter for next protocol    
    @property
    def packet_id(self) -> int:
        return self._packet_id
    @packet_id.setter
    def packet_id(self, value: int):
        self._packet_id = value    
    # @property
    # def next_protocol(self) -> Union[IP_HEADER,ARP_PACKET,OTHER_PROTOCOL]:
    #     return self._other_protocol
    # @next_protocol.setter
    # def next_protocol(self, value: Union[IP_HEADER, ARP_PACKET, OTHER_PROTOCOL]):
    #     self._other_protocol = value

    @property
    def destination_mac(self) -> bytes:
        return self._destination_mac

    @destination_mac.setter
    def destination_mac(self, value: bytes):
        if len(value) != 6:
            raise ValueError("MAC address must be 6 bytes long")
        self._destination_mac = value

    # Getter and setter for source_mac
    @property
    def source_mac(self) -> bytes:
        return self._source_mac

    @source_mac.setter
    def source_mac(self, value: bytes):
        if len(value) != 6:
            raise ValueError("MAC address must be 6 bytes long")
        self._source_mac = value

    # Getter and setter for ethernet_type
    @property
    def ethernet_type(self) -> bytes:
        return self._ethernet_type

    @ethernet_type.setter
    def ethernet_type(self, value: bytes):
        if len(value) != 2:
            raise ValueError("Ethernet type must be 2 bytes long")
        self._ethernet_type = value

    # Getter for timestamp (no setter needed, as it's set on initialization)
    @property
    def timestamp(self) -> datetime:
        return self._timestamp

    # Getter and setter for parser (if needed)
    @property
    def parser(self) -> Packet_parser:  # Assuming Packet_parser is a class
        return self._parser

    @parser.setter
    def parser(self, value: Packet_parser):
        if not isinstance(value, Packet_parser):
            raise ValueError("parser must be an instance of the Packet_parser class")
        self._parser = value



if __name__ == "__main__":

    eth_frame = Ethernet_Frame()









