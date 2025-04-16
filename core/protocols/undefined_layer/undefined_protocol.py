



class OTHER_PROTOCOL:
    
    def __init__(self, all_bytes: bytearray, parser: Packet_parser):
        
        self._parser: Packet_parser = parser
        self._parser.packet_type = type(self)
        self._other_protocol_size: int = len(all_bytes)
        self._protocol_data: bytearray = all_bytes

        self._parser.store_and_track_bytes(self._protocol_data)

    @property
    def parser(self) -> Packet_parser:
        return self._parser

    @parser.setter
    def parser(self, value: Packet_parser) -> None:
        self._parser = value
        self._parser.packet_type = type(self)

    @property
    def other_protocol_size(self) -> int:
        return self._other_protocol_size

    @other_protocol_size.setter
    def other_protocol_size(self, value: int) -> None:
        self._other_protocol_size = value

    @property
    def protocol_data(self) -> bytearray:
        return self._protocol_data

    @protocol_data.setter
    def protocol_data(self, value: bytearray) -> None:
        self._protocol_data = value
