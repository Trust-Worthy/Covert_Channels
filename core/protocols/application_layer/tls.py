from typing import Optional

from core.processing.parser import Packet_parser

class TLS_Packet:
    
    def __init__(self, parser: Packet_parser):

        ### TO-DO ##
        # implement the parser 
        self.tls_record_data: Optional[bytes] = None
        self.handshake_type: Optional[bytes] = None  # Offset: Byte 5 (1 byte)
        self.handshake_length: Optional[bytes] = None  # Offset: Bytes 6-9 (4 bytes)
        
        self.client_hello_version: Optional[bytes] = None  # Offset: Bytes 10-11 (2 bytes, TLS 1.2 only)
        self.random_bytes: Optional[bytes] = None  # Offset: Bytes 12-43 (32 bytes, TLS 1.2 only)
        self.session_id_length: Optional[bytes] = None  # Offset: Byte 44 (1 byte, TLS 1.2 only)
        self.session_id: Optional[bytes] = None
        self.cipher_suites_length: Optional[bytes] = None
        self.cipher_suites: Optional[bytes] = None
        self.compression_methods_length: Optional[bytes] = None
        self.compression_methods: Optional[bytes] = None
        self.extensions_length: Optional[bytes] = None
        self.extensions: Optional[bytes] = None
        
        self.tls_13_record_data: Optional[bytes] = None
        self.encrypted_application_data: Optional[bytes] = None

    @classmethod
    def from_bytes(cls, data: bytes) -> "TLS_Packet":
        tls_packet = cls()
        tls_packet.parse_tls(data)
        return tls_packet

    def parse_tls(self, data: bytes):
        if data[0:1] == b'\x16' and data[1:2] == b'\x03':
            version = data[1:3]
            if version == b'\x03\x03':  # TLS 1.2
                self._parse_tls_1_2(data)
            elif version == b'\x03\x04':  # TLS 1.3
                self._parse_tls_1_3(data)

    def _parse_tls_1_2(self, data: bytes):
        self.client_hello_version = data[10:12]
        self.random_bytes = data[12:44]
        self.session_id_length = data[44:45]
        session_id_len = int.from_bytes(self.session_id_length, 'big')
        self.session_id = data[45:45 + session_id_len]
        offset = 45 + session_id_len
        self.cipher_suites_length = data[offset:offset + 2]
        cipher_suites_len = int.from_bytes(self.cipher_suites_length, 'big')
        self.cipher_suites = data[offset + 2:offset + 2 + cipher_suites_len]
        offset += 2 + cipher_suites_len
        self.compression_methods_length = data[offset:offset + 1]
        comp_methods_len = int.from_bytes(self.compression_methods_length, 'big')
        self.compression_methods = data[offset + 1:offset + 1 + comp_methods_len]
        offset += 1 + comp_methods_len
        self.extensions_length = data[offset:offset + 2]
        ext_len = int.from_bytes(self.extensions_length, 'big')
        self.extensions = data[offset + 2:offset + 2 + ext_len]

    def _parse_tls_1_3(self, data: bytes):
        self.tls_13_record_data = data[5:]  # Capture full record data for TLS 1.3
        self.encrypted_application_data = data[5:]  # Since everything after handshake is encrypted

    @property
    def get_tls_record_data(self) -> Optional[bytes]:
        return self.tls_record_data

    @property
    def get_handshake_type(self) -> Optional[bytes]:
        return self.handshake_type

    @property
    def get_encrypted_application_data(self) -> Optional[bytes]:
        return self.encrypted_application_data
