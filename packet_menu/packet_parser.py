import numpy as np


class Packet_parser:
    """
    Packet Parser class exists to track important offset information and track all the bytes for the MLP model.
    After packet is parsed, a numpy array will be initialized in preparation for machine learning with pytorch.
    """
    def __init__(self):
        """
        Initializes packet parser with empty values.
        """
        
        self._offset_pointer: int = 0
        self._total_bytes_read: int = 0
        self._packet_data_bytes: bytearray  # Full packet data in bytes
        self._packet_data_np_arr: np.ndarray  # Full packet data as a NumPy array
        self._finished_parsing: bool ### flag needs to be set when the last nested protocol is finished being parsed


    def store_and_track_bytes(self, offset:int , all_bytes: bytes) -> None:
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
        self.packet_data_bytes = all_bytes ### Adding bytes to the entire byte array .append under the hood in the setter
        self.packet_data_np_arr = self.packet_data_bytes
        


    @property
    def offset_pointer(self) -> int:
        return self._offset_pointer
    
    @offset_pointer.setter
    def move_byte_pointer(self,value: bytes) -> None:
        
        self._offset_pointer += len(value)


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
