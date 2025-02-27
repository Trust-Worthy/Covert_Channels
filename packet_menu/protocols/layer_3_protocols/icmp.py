
from layer_2_protocols.ethernet import Ethernet_Frame

class ICMP_MESSAGE(Ethernet_Frame):
    pass

@dataclass
class ICMP_REQUEST:
    pass

@dataclass
class ICMP_REPLY:
    pass