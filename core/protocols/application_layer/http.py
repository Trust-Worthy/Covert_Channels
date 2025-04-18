from typing import Optional, Dict



class HTTP:
    def __init__(self, raw_data: bytes, parser: Packet_parser):
        
        ### TO-DO###
        # properly implement the parser so that it tracks all the tracked bytes
        self._parser = parser
        self._parser.packet_type = type(self)

        self.is_request: Optional[bool] = None  # True if request, False if response
        self.method: Optional[bytes] = None  # Only for requests
        self.request_uri: Optional[bytes] = None  # Only for requests
        self.http_version: Optional[bytes] = None  # In both requests and responses
        
        self.status_code: Optional[bytes] = None  # Only for responses
        self.status_message: Optional[bytes] = None  # Only for responses
        
        self.headers: Dict[bytes, bytes] = {}  # Headers dictionary
        self.body: Optional[bytes] = None  # Optional body
        
        self.parse(raw_data)  # Parse the raw HTTP data when an instance is created

        if not self._parser.check_if_finished_parsing():
            raise ValueError("There should be no bytes left bruh")

    def parse(self, raw_data: bytes):
        # Separate headers and body
        header_section, body_section = raw_data.split(b"\r\n\r\n", 1) if b"\r\n\r\n" in raw_data else (raw_data, b"")
        
        # Split headers into lines
        header_lines = header_section.split(b"\r\n")
        
        if not header_lines:
            return
        
        # Split the first line (Request-Line or Status-Line)
        first_line_parts = header_lines[0].split(b" ")
        
        if first_line_parts[0].startswith(b"HTTP/"):
            # This is a response
            self.is_request = False
            self.http_version = first_line_parts[0]  # e.g., HTTP/1.1
            self.status_code = first_line_parts[1]  # e.g., 200
            self.status_message = b" ".join(first_line_parts[2:])  # e.g., OK
        else:
            # This is a request
            self.is_request = True
            self.method = first_line_parts[0]  # e.g., GET
            self.request_uri = first_line_parts[1]  # e.g., /index.html
            self.http_version = first_line_parts[2]  # e.g., HTTP/1.1
        
        # Parse headers
        for line in header_lines[1:]:
            if b": " in line:
                key, value = line.split(b": ", 1)
                self.headers[key] = value
        
        # Store body
        self.body = body_section

    # Getter for parser, no setter
    @property
    def parser(self) -> Packet_parser:
        return self._parser

    @property
    def get_method(self) -> Optional[bytes]:
        return self.method

    @property
    def get_request_uri(self) -> Optional[bytes]:
        return self.request_uri

    @property
    def get_status_code(self) -> Optional[bytes]:
        return self.status_code

    @property
    def get_status_message(self) -> Optional[bytes]:
        return self.status_message

    @property
    def get_headers(self) -> Dict[bytes, bytes]:
        return self.headers

    @property
    def get_body(self) -> Optional[bytes]:
        return self.body



