"""
Author: @Trust-Worthy

File: tests/protocols/test_ethernet.py
"""
import pytest
import dpkt

from core.protocols.layer_2_protocols.ethernet import Ethernet_Frame



def test_ethernet_frame_creation():
    with open("../test_data/ethernet_test.pcap","rb") as file:
        # 1. Open pcap file in binary mode 
        pcap = dpkt.pcap.Reader(file)
        
        # 2. Iterate over captured packets
        ts, buf = next(iter(pcap)) # first pcap only
            # ts = timestamp when packet was captured
            # buf = raw bytes of the packet
            
        eth = Ethernet_Frame(timestamp_data=ts, all_bytes=buf)
        
        # Compare with known expected values
        assert eth.destination_mac == b"\xc4\x4f\xd5\xc7\xd1\x07"
        assert eth.source_mac == b"\xc4\x4f\xd5\xc7\xd1\x07"
        assert eth.ethernet_type == b"\x08\x00"