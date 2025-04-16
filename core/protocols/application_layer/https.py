
from typing import Optional




class HTTPS(HTTP):
    def __init__(self, parser: Packet_parser, raw_data: bytes, is_encrypted: bool = True):
        
        ### TO-DO ###
        ## properly implement the parser...

        self._parser = parser
        self._parser.packet_type = type(self)
        
        self.is_encrypted: bool = is_encrypted
        self.encrypted_data: Optional[bytes] = None
        self.decrypted_http: Optional[HTTP] = None

        if self.is_encrypted:
            # Store encrypted data — don't parse it yet
            self.encrypted_data = raw_data
        else:
            # If data is already decrypted, parse like normal HTTP
            super().__init__(raw_data)

    def decrypt_tls_payload(self, key_material: bytes):
        """
        Simulate decryption and parse HTTP. Replace this logic with real decryption when ready.
        """
        if not self.encrypted_data:
            raise ValueError("No encrypted data available to decrypt.")

        # Fake decryption for now
        decrypted_data = self._fake_tls_decrypt(self.encrypted_data, key_material)

        # Parse the decrypted HTTP data using parent class
        self.decrypted_http = HTTP(decrypted_data)
        self.is_encrypted = False

        # Optionally populate HTTP attributes from the decrypted version
        self._copy_decrypted_http_fields()

    def _fake_tls_decrypt(self, encrypted_data: bytes, key_material: bytes) -> bytes:
        # Placeholder: Replace with actual TLS decryption logic
        return b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"

    def _copy_decrypted_http_fields(self):
        """
        Copy parsed values from self.decrypted_http into self.
        """
        if self.decrypted_http:
            self.is_request = self.decrypted_http.is_request
            self.method = self.decrypted_http.method
            self.request_uri = self.decrypted_http.request_uri
            self.http_version = self.decrypted_http.http_version
            self.status_code = self.decrypted_http.status_code
            self.status_message = self.decrypted_http.status_message
            self.headers = self.decrypted_http.headers
            self.body = self.decrypted_http.body

    @property
    def parser(self) -> Packet_parser:
        return self._parser
    
    @property
    def get_encrypted_status(self) -> bool:
        return self.is_encrypted
