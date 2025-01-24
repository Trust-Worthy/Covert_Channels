'''
@Author Trust-Worthy

'''


from dataclasses import dataclass


@dataclass
class Packet:
    destination_mac: str # Offset: Bytes 1-6. Destination MAC is the first 6 bytes
    source_mac: str # Offset: Bytes 7-12. Source MAC is the second set of six bytes



@dataclass
class DHCP:



@dataclass
class TCP:


@dataclass
class TLS


@dataclass
class ARP

@dataclass
class ICMP

@dataclass
class OTHER