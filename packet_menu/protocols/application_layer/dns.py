
from cleaning_captures.packet_parser import Packet_parser

class DNS:  
    def __init__(self, all_bytes: bytes, parser:Packet_parser, over_tcp: bool = False):
        
        ## Pass on the parser to the next protocol.
        self._parser: Packet_parser = parser
        self._parser._packet_type = type(self) ## log the packet type for logging / debugging
        
        ### depending on the size 
        self._over_tcp: bool = over_tcp

        ### query of response
        self._is_query: bool

        self._transaction_id: bytes
        self._flags: bytes
        self._questions: bytes
        self._answer_rr: bytes
        self._authority_rr: bytes
        self._additional_rr: bytes
        self._queries: bytes
        self._answers: bytes
        self._authoritative_nameservers: bytes
        self._additional_records: bytes


        self._qdcount: int  # number of questions
        self._ancount: int  # number of answers
        self._nscount: int  # number of authority records
        self._arcount: int  # number of additional records

        # Optional: parsed flags
        self._opcode: int
        self._aa: bool
        self._tc: bool
        self._rd: bool
        self._ra: bool
        self._rcode: int
            
    def parse_dns_query():
        pass
    def get_remaining_bytes_after_dns():
        pass



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