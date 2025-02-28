


class DNS:


    def __init__(self, all_bytes: bytes, over_tcp: bool = False):
        
        
        ### depending on the size 
        self._over_tcp: bool = over_tcp

        ### query of response
        self._is_query: bool