


from typing import NamedTuple

from core import Packet_parser

class DNSQuery(NamedTuple):
    """
    Mini-class to capture the type of the dns query.

    Args:
        NamedTuple (_type_): inheriting namedTuple and implementing it for my dns class

    Returns:
        _type_: filled in dns query with the qname, qtype, and qclass filled in
    """
    qname: str     # e.g., "www.example.com"
    qtype: int     # 1 = A, 28 = AAAA, etc.
    qclass: int    # 1 = IN (Internet)

class DNSResourceRecord:
    name: str
    type: int
    class_: int
    ttl: int
    data: bytes 

class DNS:  
    def __init__(self, all_bytes: bytes, parser:Packet_parser, over_tcp: bool = False):
        
        ## Pass on the parser to the next protocol.
        self._parser: Packet_parser = parser
        self._parser._packet_type = type(self) ## log the packet type for logging / debugging
        
        ## Transaction ID — 16 bits (2 bytes)
        self._transaction_id: bytes  # A unique identifier for matching queries and responses (2 bytes)

        ### Flags — 16 bits (2 bytes total), broken down into several subfields
        self._flags: bytes  # The raw 2-byte flags field

        # Parsed flags from `_flags` (optional but useful to break out):
        self._is_query: bool         # 1 bit: 0 = query, 1 = response (QR flag)
        self._opcode: int            # 4 bits: Operation code (0 = standard query, 1 = inverse, etc.)
        self._aa: bool               # 1 bit: Authoritative Answer
        self._tc: bool               # 1 bit: Truncated message
        self._rd: bool               # 1 bit: Recursion Desired
        self._ra: bool               # 1 bit: Recursion Available
        self._rcode: int             # 4 bits: Response code (e.g., 0 = No error, 3 = NXDOMAIN)

        ### Counts (each 16 bits = 2 bytes)
        self._qdcount: int  # Number of entries in the question section
        self._ancount: int  # Number of resource records in the answer section
        self._nscount: int  # Number of name server authority records
        self._arcount: int  # Number of additional resource records

        ### Question Section (variable length, repeats qdcount times)
        self._questions: bytes   # Raw bytes of question section (used during initial parsing)
        self._queries: list[DNSQuery]  # Parsed version (e.g.,  (name, type, class))

        ### Answer Section (variable length, repeats ancount times)
        self._answer_rr: bytes   # Raw bytes of answer section
        self._answers: list[DNSResourceRecord]    # Parsed list of resource records

        ### Authority Section (variable length, repeats nscount times)
        self._authority_rr: bytes                    # Raw authority section bytes
        self._authoritative_nameservers: list[DNSResourceRecord]       # Parsed list of NS records

        ### Additional Section (variable length, repeats arcount times)
        self._additional_rr: bytes     # Raw bytes of additional section
        self._additional_records: list[DNSResourceRecord]  # Parsed list of additional records (OPT, A, etc.)

        ### Transport (not part of DNS spec, but necessary for parsing context)
        self._over_tcp: bool = over_tcp # Indicates if the DNS packet was received over TCP instead of UDP
        self._has_extra_bytes:bool = False
        self._remaining_bytes: bytearray

        self.parse_dns_message(all_bytes)

        if not self._parser.check_if_finished_parsing():
            remaining_bytes = self.get_remaining_bytes_after_dns()


    def parse_dns_message(self,all_bytes:bytearray) -> None:
        """
        DNS has a variable number of bytes. This function accurately parses the DNS info according to 
        """

        self._transaction_id = all_bytes[:2]
        self._flags = all_bytes[2:4]
        flags_hi = self._flags[0]  # high byte
        flags_lo = self._flags[1]  # low byte

        self._is_query = bool(flags_hi & 0b10000000)  # 1st bit: QR
        self._opcode = (flags_hi & 0b01111000) >> 3
        self._aa = bool(flags_hi & 0b00000100)           # Bit 2
        self._tc = bool(flags_hi & 0b00000010)           # Bit 1
        self._rd = bool(flags_hi & 0b00000001)           # Bit 0

        self._ra = bool(flags_lo & 0b10000000)           # Bit 7
        self._rcode = flags_lo & 0b00001111              # Bits 3-0
        
        self._qdcount = int.from_bytes(all_bytes[4:6], 'big')
        self._ancount = int.from_bytes(all_bytes[6:8], 'big')
        self._nscount = int.from_bytes(all_bytes[8:10], 'big')
        self._arcount = int.from_bytes(all_bytes[10:12], 'big')

        ### guaranteed to be 12 bytes before question section.

        offset: int = 12 

        offset = self.parse_dns_questions_section(all_bytes, offset)
        offset = self.parse_dns_answer_section(all_bytes,offset)
        offset = self.parse_dns_authority_section(all_bytes,offset)
        offset = self.parse_dns_additional_section(all_bytes,offset)


        self._parser.store_and_track_bytes(offset)
        if not self._parser.check_if_finished_parsing():
            self._has_extra_bytes = True
            self.get_remaining_bytes_after_dns()

    def parse_dns_questions_section(self, all_bytes: bytearray, offset:int) -> int:
        # Question Section

        # self._questions = all_bytes[offset:offset + self._qdcount * 4]  # Question section bytes (each question is at least 4 bytes)
        self._queries = []
        
        # Example parsing of domain name, type, and class for each question

        for _ in range(self._qdcount):
            domain_name, qtype, qclass = self._parse_question(all_bytes[offset:])
            self._queries.append(DNSQuery(domain_name, qtype, qclass))
            _, domain_len = self._parse_domain_name(all_bytes[offset:])
            offset += domain_len + 4  # domain name + type (2) + class (2)
           
        return offset

    def parse_dns_answer_section(self, all_bytes:bytearray, offset) -> int:
        # Answer Section
        ### did I do this parsing correctly below?
        # self._answer_rr = all_bytes[offset + self._qdcount * 4: offset + self._qdcount * 4 + self._ancount * 12]  # Answer section bytes
        self._answers = []

        '''CONTINUE HERE'''
            # Parse answer section
        for _ in range(self._ancount):
            rr_name, rr_type, rr_class, rr_ttl,rdlength, rr_data = self._parse_resource_record(all_bytes[offset:])
            self._answers.append(DNSResourceRecord(rr_name, rr_type, rr_class, rr_ttl, rr_data))
            _, consumed = self._parse_domain_name(all_bytes[offset:])
            offset += consumed + 10 + rdlength
            
        
        return offset
    def parse_dns_authority_section(self, all_bytes:bytearray, offset) -> int:
        # Authority Section
        # self._authority_rr = all_bytes[offset: offset + self._nscount * 12]  # Authority section bytes
        self._authoritative_nameservers = []

        # Parse authority section (NS records)
        for _ in range(self._nscount):
            ns_name, ns_type, ns_class, ns_ttl, rdlength, ns_data = self._parse_resource_record(all_bytes[offset:])
            self._authoritative_nameservers.append(DNSResourceRecord(ns_name, ns_type, ns_class, ns_ttl, ns_data))
            _, consumed = self._parse_domain_name(all_bytes[offset:])
            offset += consumed + 10 + rdlength

        return offset
    def parse_dns_additional_section(self, all_bytes:bytearray, offset) -> int:

        # Additional Section
        #self._additional_rr = all_bytes[offset: offset + self._arcount * 12]  # Additional section bytes
        self._additional_records = []

        # Parse additional section (records like A, AAAA, OPT)
        for _ in range(self._arcount):
            add_name, add_type, add_class, add_ttl, rdlength, add_data = self._parse_resource_record(all_bytes[offset:])
            self._additional_records.append(DNSResourceRecord(add_name, add_type, add_class, add_ttl, add_data))
            _, consumed = self._parse_domain_name(all_bytes[offset:])
            offset += consumed + 10 + rdlength
        return offset
    def get_remaining_bytes_after_dns(self, all_bytes:bytearray, offset) -> bytearray:

        

        remaining_bytes: bytearray = all_bytes[self._parser.offset_pointer:]
        
        return remaining_bytes
        
    def is_over_tcp(dns_packet_bytes: bytes) -> bool:
        # Check for a 2-byte length prefix (common in TCP DNS)
        return len(dns_packet_bytes) >= 2 and int.from_bytes(dns_packet_bytes[:2], 'big') == len(dns_packet_bytes[2:])

    def _parse_question(self, data: bytearray) -> tuple[str, int, int]:
        domain_name, consumed = self._parse_domain_name(data)
        qtype = int.from_bytes(data[consumed:consumed + 2], 'big')
        qclass = int.from_bytes(data[consumed + 2:consumed + 4], 'big')
        return domain_name, qtype, qclass

    def _parse_resource_record(self, data: bytearray) -> tuple[str, int, int, int, bytes]:
        name, consumed = self._parse_domain_name(data)
        rtype = int.from_bytes(data[consumed:consumed + 2], 'big')
        rclass = int.from_bytes(data[consumed + 2:consumed + 4], 'big')
        ttl = int.from_bytes(data[consumed + 4:consumed + 8], 'big')
        rdlength = int.from_bytes(data[consumed + 8:consumed + 10], 'big')
        rdata = data[consumed + 10:consumed + 10 + rdlength]
        total_consumed = consumed + 10 + rdlength
        return name, rtype, rclass, ttl, rdlength, rdata
    
    def _parse_domain_name(self, data: bytearray) -> tuple[str, int]:
        labels = []
        offset = 0
        jumped = False
        jump_offset = 0

        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                # Compression pointer
                if not jumped:
                    jump_offset = offset + 2
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                label, _ = self._parse_domain_name(data[pointer:])
                labels.append(label)
                offset += 2
                jumped = True
                break
            else:
                offset += 1
                labels.append(data[offset:offset + length].decode())
                offset += length

        return '.'.join(labels), (jump_offset if jumped else offset)


     # --- Flags ---

    @property
    def flags(self) -> bytes: return self._flags
    @flags.setter
    def flags(self, value: bytes) -> None: self._flags = value

    @property
    def is_query(self) -> bool: return self._is_query
    @is_query.setter
    def is_query(self, value: bool) -> None: self._is_query = value

    @property
    def opcode(self) -> int: return self._opcode
    @opcode.setter
    def opcode(self, value: int) -> None: self._opcode = value

    @property
    def aa(self) -> bool: return self._aa
    @aa.setter
    def aa(self, value: bool) -> None: self._aa = value

    @property
    def tc(self) -> bool: return self._tc
    @tc.setter
    def tc(self, value: bool) -> None: self._tc = value

    @property
    def rd(self) -> bool: return self._rd
    @rd.setter
    def rd(self, value: bool) -> None: self._rd = value

    @property
    def ra(self) -> bool: return self._ra
    @ra.setter
    def ra(self, value: bool) -> None: self._ra = value

    @property
    def rcode(self) -> int: return self._rcode
    @rcode.setter
    def rcode(self, value: int) -> None: self._rcode = value

    # --- Counts ---

    @property
    def qdcount(self) -> int: return self._qdcount
    @qdcount.setter
    def qdcount(self, value: int) -> None: self._qdcount = value

    @property
    def ancount(self) -> int: return self._ancount
    @ancount.setter
    def ancount(self, value: int) -> None: self._ancount = value

    @property
    def nscount(self) -> int: return self._nscount
    @nscount.setter
    def nscount(self, value: int) -> None: self._nscount = value

    @property
    def arcount(self) -> int: return self._arcount
    @arcount.setter
    def arcount(self, value: int) -> None: self._arcount = value

    # --- Question Section ---

    @property
    def questions(self) -> bytes: return self._questions
    @questions.setter
    def questions(self, value: bytes) -> None: self._questions = value

    @property
    def queries(self) -> list['DNSQuery']: return self._queries
    @queries.setter
    def queries(self, value: list['DNSQuery']) -> None: self._queries = value

    # --- Answer Section ---

    @property
    def answer_rr(self) -> bytes: return self._answer_rr
    @answer_rr.setter
    def answer_rr(self, value: bytes) -> None: self._answer_rr = value

    @property
    def answers(self) -> list['DNSResourceRecord']: return self._answers
    @answers.setter
    def answers(self, value: list['DNSResourceRecord']) -> None: self._answers = value

    # --- Authority Section ---

    @property
    def authority_rr(self) -> bytes: return self._authority_rr
    @authority_rr.setter
    def authority_rr(self, value: bytes) -> None: self._authority_rr = value

    @property
    def authoritative_nameservers(self) -> list['DNSResourceRecord']:
        return self._authoritative_nameservers
    @authoritative_nameservers.setter
    def authoritative_nameservers(self, value: list['DNSResourceRecord']) -> None:
        self._authoritative_nameservers = value

    # --- Additional Section ---

    @property
    def additional_rr(self) -> bytes: return self._additional_rr
    @additional_rr.setter
    def additional_rr(self, value: bytes) -> None: self._additional_rr = value

    @property
    def additional_records(self) -> list['DNSResourceRecord']:
        return self._additional_records
    @additional_records.setter
    def additional_records(self, value: list['DNSResourceRecord']) -> None:
        self._additional_records = value

    # --- Transport Info ---

    @property
    def over_tcp(self) -> bool: return self._over_tcp
    @over_tcp.setter
    def over_tcp(self, value: bool) -> None: self._over_tcp = value

    @property
    def has_extra_bytes(self) -> bool: return self._has_extra_bytes
    @has_extra_bytes.setter
    def has_extra_bytes(self, value: bool) -> None: self._has_extra_bytes = value

    # Getter for parser, no setter
    @property
    def parser(self) -> Packet_parser:
        return self._parser