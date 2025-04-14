
from cleaning_captures.packet_parser import Packet_parser

from typing import NamedTuple

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
        self._authoritative_nameservers: bytes       # Parsed list of NS records

        ### Additional Section (variable length, repeats arcount times)
        self._additional_rr: bytes     # Raw bytes of additional section
        self._additional_records: bytes  # Parsed list of additional records (OPT, A, etc.)

        ### Transport (not part of DNS spec, but necessary for parsing context)
        self._over_tcp: bool = over_tcp # Indicates if the DNS packet was received over TCP instead of UDP


    def parse_dns_packet():
        """
        DNS has a variable number of bytes. This function accurately parses the DNS info according to 
        """
    def get_remaining_bytes_after_dns():
        pass

    def is_over_tcp(dns_packet_bytes: bytes) -> bool:
        # Check for a 2-byte length prefix (common in TCP DNS)
        return len(dns_packet_bytes) >= 2 and int.from_bytes(dns_packet_bytes[:2], 'big') == len(dns_packet_bytes[2:])




    @property
    def over_tcp(self) -> bool:
        return self._over_tcp

    @over_tcp.setter
    def over_tcp(self, value: bool):
        self._over_tcp = value

    @property
    def is_query(self) -> bool:
        return self._is_query

    @is_query.setter
    def is_query(self, value: bool):
        self._is_query = value

    @property
    def transaction_id(self) -> bytes:
        return self._transaction_id

    @transaction_id.setter
    def transaction_id(self, value: bytes):
        self._transaction_id = value

    @property
    def flags(self) -> bytes:
        return self._flags

    @flags.setter
    def flags(self, value: bytes):
        self._flags = value

    @property
    def questions(self) -> bytes:
        return self._questions

    @questions.setter
    def questions(self, value: bytes):
        self._questions = value

    @property
    def answer_rr(self) -> bytes:
        return self._answer_rr

    @answer_rr.setter
    def answer_rr(self, value: bytes):
        self._answer_rr = value

    @property
    def authority_rr(self) -> bytes:
        return self._authority_rr

    @authority_rr.setter
    def authority_rr(self, value: bytes):
        self._authority_rr = value

    @property
    def additional_rr(self) -> bytes:
        return self._additional_rr

    @additional_rr.setter
    def additional_rr(self, value: bytes):
        self._additional_rr = value

    @property
    def queries(self) -> bytes:
        return self._queries

    @queries.setter
    def queries(self, value: bytes):
        self._queries = value

    @property
    def answers(self) -> bytes:
        return self._answers

    @answers.setter
    def answers(self, value: bytes):
        self._answers = value

    @property
    def authoritative_nameservers(self) -> bytes:
        return self._authoritative_nameservers

    @authoritative_nameservers.setter
    def authoritative_nameservers(self, value: bytes):
        self._authoritative_nameservers = value

    @property
    def additional_records(self) -> bytes:
        return self._additional_records

    @additional_records.setter
    def additional_records(self, value: bytes):
        self._additional_records = value