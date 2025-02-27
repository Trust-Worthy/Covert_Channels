import numpy as np
from typing import Union, Optional

from protocols.layer_2_protocols.ethernet import Ethernet_Frame
from protocols.layer_3_protocols import arp, icmp ,ip
from protocols.layer_4_protocols import tcp,udp
from protocols.application_layer import http,dns, quic, tls
from protocols.undefined_layer import undefined_protocol as undef


class Packet_parser:
    """
    Packet Parser class exists to track important offset information and track all the bytes for the MLP model.
    After packet is parsed, a numpy array will be initialized in preparation for machine learning with pytorch.
    """
    def __init__(self):
        """
        Initializes packet parser with empty values.
        """
        #Most parsers move sequentially through a buffer, so it makes sense to begin at the next available byte after what’s already parsed.
        self._offset_pointer: int = 0 ### references the index to start the next parsing operation
        
        self._total_bytes_read: int = 0 ### counts total bytes read
        self._packet_data_bytes: bytearray  # Full packet data in bytes
        self._packet_data_np_arr: np.ndarray  # Full packet data as a NumPy array
        self._finished_parsing: bool ### flag needs to be set when the last nested protocol is finished being parsed
        self._packet_type: Union[
            arp.ARP_PACKET,
            icmp.ICMP_MESSAGE,
            ip.IP_HEADER,
            tcp.TCP_SEGMENT,
            udp.UDP_DATAGRAM,
            http.HTTP_Packet,
            dns.DNS,
            quic.QUIC,
            tls.TLS_Packet,
            undef.OTHER_PROTOCOL]

    def store_and_track_bytes(self, offset:int , all_bytes: bytes = None, is_eth: bool = False) -> None:
        """
        Updates byte_pointer, total_bytes_read, and appends the bytes to the packet data bytes.

        Anytime the byte_pointer is moved, update...
        
        1) The byte_pointer itself
        2) The total_bytes_read
        3) The byte array containing all the packet data. packet_data_bytes

        Args:
            all_bytes (bytes): All the bytes captured in the packet.

        """

        self.move_byte_pointer = offset ### Moving byte pointer to the next offset internally doing +=
        self.total_bytes_read = offset ###  += under the hood in the setter

        if is_eth:
            self.packet_data_bytes = all_bytes ### Adding bytes to the entire byte array .append under the hood in the setter
            self.packet_data_np_arr = self.packet_data_bytes
   
    def check_if_finished_parsing(self)-> bool:
        """
        This function checks if the offset_pointer and total_bytes_read fields
        match the length of all the bytes that need to be processe.

        Final state: total_bytes_read should equal the length of the packet_data_bytes
                     offset_pointer shoud equal the length of the pacaket_data_byes minus 1 (bc of list indexing)

        Returns:
            bool: returns True if offset_pointer and total_bytes_read equal the length of packet_data_bytes
        """
        if self.total_bytes_read == len(self.packet_data_bytes) and self.offset_pointer == (len(self.packet_data_bytes)): #### CAUTION with - 1 here
            
            return True
        else:
            return False
        
    @property
    def packet_type(self) -> Union[
            arp.ARP_PACKET,
            icmp.ICMP_MESSAGE,
            ip.IP_HEADER,
            tcp.TCP_SEGMENT,
            udp.UDP_DATAGRAM,
            http.HTTP_Packet,
            dns.DNS,
            quic.QUIC,
            tls.TLS_Packet,
            undef.OTHER_PROTOCOL]:

        return self._packet_type
    
    @packet_type.setter
    def packet_type(self, value:Union[
            arp.ARP_PACKET,
            icmp.ICMP_MESSAGE,
            ip.IP_HEADER,
            tcp.TCP_SEGMENT,
            udp.UDP_DATAGRAM,
            http.HTTP_Packet,
            dns.DNS,
            quic.QUIC,
            tls.TLS_Packet,
            undef.OTHER_PROTOCOL]):
        self._packet_type = value

    @property
    def offset_pointer(self) -> int:
        return self._offset_pointer
    
    @offset_pointer.setter
    def move_byte_pointer(self, value) -> None:
        
        self._offset_pointer += value


    @property
    def total_bytes_read(self)-> int:
        return self._total_bytes_read
    
    @total_bytes_read.setter
    def total_bytes_read(self,value:int) -> None:
        self._total_bytes_read += value

    
    @property
    def packet_data_bytes(self) -> bytearray:
        return self._packet_data_bytes
    
    @packet_data_bytes.setter
    def packet_data_bytes(self, value:bytes) -> None:
        self._packet_data_bytes.append(value)

    @property
    def packet_data_np_arr(self) -> np.ndarray: 
        return self._packet_data_np_arr
    
    @packet_data_np_arr.setter
    def packet_data_np_arr(self,value: bytearray) -> None:
        self._packet_data_np_arr = np.frombuffer(value,dtype=np.uint8)
