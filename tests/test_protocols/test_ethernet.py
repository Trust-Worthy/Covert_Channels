"""
@Author: Trust-Worthy

Comprehensive test suite for EthernetFrame class - TDD approach
All tests should FAIL initially, then pass as you implement the class.

Run with: python -m pytest tests/protocols/test_ethernet.py -v
"""

import pytest
from datetime import datetime
from covert_hunter.protocols.ethernet import EthernetFrame

class TestEthernetWithRealData:
    
    def test_ethernet_parsing_with_real_data(self, real_ethernet_data):
        """Test parsing with real packet data from pcap file."""
        
        # Use the real data from pcap file

        frame = EthernetFrame(
            timestamp=real_ethernet_data['timestamp'],
            all_bytes= real_ethernet_data['data']
        )
        
        # Basic assertions
        assert len(frame.destination_mac) == 6
        assert len(frame.source_mac) == 6
        assert len(frame.ethernet_type) == 2
        
        print(f"Real data parsed successfully!")
        print(f"  Timestamp: {real_ethernet_data['timestamp']}")
        print(f"  Dst MAC: {frame.destination_mac.hex(':')}")
        print(f"  Src MAC: {frame.source_mac.hex(':')}")
        print(f"  EtherType: 0x{frame.ethernet_type.hex()}")
        
    def test_ethernet_timestamp_invalid(self):
        frame = EthernetFrame()
        with pytest.raises(TypeError):
            frame.timestamp = "not datetime object"
    def test_ethernet_destination_mac_invalid(self):
        frame = EthernetFrame()
        with pytest.raises(ValueError):
            frame.destination_mac = b"\x01\x02"
    def test_ethernet_source_mac_invalid(self):
        frame = EthernetFrame()
        with pytest.raises(ValueError):
            frame.source_mac = b"\x01\x02"
    def test_ethernet_type_invalid(self):
        frame = EthernetFrame()
        with pytest.raises(ValueError):
            frame.ethernet_type = b"\x02"
    
class TestEthernetClassFunctions:
    
    def test_check_bytes_valid(self, real_ethernet_data):
        frame = EthernetFrame()
        assert frame.check_bytes(real_ethernet_data['data']) is True
        
    def test_check_bytes_invalid(self):
        frame = EthernetFrame()
        with pytest.raises(TypeError):
            frame.check_bytes("not bytses") # str instead of bytes
            
    def test_check_bytes_len_invalid(self):
        frame = EthernetFrame()
        with pytest.raises(ValueError):
            frame.check_bytes(b"\x01\x92") # Ethernet Frame is less than 14 bytes
            
    def test_parse_ethernet_frame_valid(self, real_ethernet_data):
        
        frame = EthernetFrame(
            timestamp=real_ethernet_data['timestamp'],
            all_bytes= real_ethernet_data['data']
        )
        
        assert frame.destination_mac == bytes.fromhex('c44fd5c7d107')
        assert frame.source_mac == bytes.fromhex("5689c323ec50")
        assert frame.ethernet_type == b"\x08\x00"
        assert frame.timestamp == datetime.fromtimestamp(1758944483.242245)

    def test_generate_unique_packet_id(self, all_ethernet_pcap_packets: list):
        frame = EthernetFrame()
        frame_ids = set()
        for packet_data in all_ethernet_pcap_packets:
            frame.parse_ethernet_frame(timestamp=packet_data['timestamp'],all_bytes=packet_data['data'])
            # ensure id hasn't already been assigned
            assert frame.packet_id not in frame_ids
            frame_ids.add(frame.packet_id)
            
    def test_ethernet_packet_id_duplicate(self, real_ethernet_data):
        frame1 = EthernetFrame()
        frame2 = EthernetFrame()
        
        with pytest.raises(ValueError):
            frame1.packet_id = 123
            frame2.packet_id = 123
    def test_ethernet_packet_id_not_int(self):
        frame = EthernetFrame()
        with pytest.raises(TypeError):
            frame.packet_id = "not an int"
        
class TestAllPcapPackets:
    
    def test_all_packets_parse_successfully(self, all_ethernet_pcap_packets):
        """Test that all 5 packets in the pcap parse without errors."""
        
        assert len(all_ethernet_pcap_packets) == 5, "Expected 5 packets in ethernet_test.pcap"
        
        for i, packet_data in enumerate(all_ethernet_pcap_packets):
            try:
                frame = EthernetFrame(
                    timestamp=packet_data['timestamp'],
                    all_bytes=packet_data['data']
                )
                print(f"Packet {i+1}: ✅ Parsed successfully")
                
            except Exception as e:
                pytest.fail(f"Packet {i+1} failed to parse: {e}")
                
    def test_first_packet_specific_values(self, all_ethernet_pcap_packets):
        """Test specific expected values from the first packet."""
        
        first_packet = all_ethernet_pcap_packets[0]
        frame = EthernetFrame(
            timestamp=first_packet['timestamp'],
            all_bytes=first_packet['data']
        )
        
        assert frame.destination_mac == bytes.fromhex('c44fd5c7d107')
        assert frame.source_mac == bytes.fromhex("5689c323ec50")
        assert int.from_bytes(frame.ethernet_type, 'big') == 0x0800  # IPv4
        
        print(f"First packet details:")
        print(f"  MAC dst: {frame.destination_mac.hex(':')}")
        print(f"  MAC src: {frame.source_mac.hex(':')}")
        print(f"  Type: 0x{frame.ethernet_type.hex()}")
        

        
        