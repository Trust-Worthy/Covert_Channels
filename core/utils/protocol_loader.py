

# Only this file touches deep protocol imports
from core.protocols.application_layer.dns import DNS
from core.protocols.application_layer.http import HTTP
from core.protocols.layer_4_protocols import TCP_HEADER
from core.protocols.layer_4_protocols import UDP_HEADER
from core.protocols.layer_3_protocols import IP_HEADER
from core.protocols.layer_3_protocols import ICMP_MESSAGE
from core.protocols.layer_2_protocols import Ethernet_Frame
from core.protocols.layer_3_protocols import ARP_PACKET
from core.protocols.undefined_layer import OTHER_PROTOCOL

# Expose a clean interface
__all__ = [
    "Ethernet_Frame", "ARP_PACKET", "ICMP_MESSAGE", "IP_HEADER",
    "TCP_HEADER", "UDP_HEADER", "OTHER_PROTOCOL",
    "DNS", "HTTP"
]