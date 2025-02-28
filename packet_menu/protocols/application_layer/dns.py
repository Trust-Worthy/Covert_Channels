


class DNS:


    def __init__(self, all_bytes: bytes, over_tcp: bool = False):
        
        
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