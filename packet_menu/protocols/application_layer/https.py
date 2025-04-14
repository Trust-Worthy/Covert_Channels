
from application_layer.http import HTTP

class HTTPS(HTTP):
    def __init__(self, raw_data: bytes):
        # HTTPS is essentially HTTP over SSL/TLS
        super().__init__(raw_data)
        self.is_encrypted: bool = True  # We know HTTPS uses encryption

    @property
    def get_encrypted_status(self) -> bool:
        return self.is_encrypted