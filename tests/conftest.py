# tests/conftest.py

import pytest
import dpkt
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import Mock
from datetime import datetime

# Path to pcap files
TEST_DATA_DIR = Path(__file__).parent / "test_data" / "protocols"
ETHERNET_PCAP_FILE = TEST_DATA_DIR / "ethernet_test.pcap"

def read_first_packet_from_pcap()-> tuple[str,bytes]: 
    """Read the first packet from ethernet_test.pcap and return timestamp + raw data."""

    if not ETHERNET_PCAP_FILE.exists():
        raise FileNotFoundError(f"Pcap file not found: {ETHERNET_PCAP_FILE}")
    
    with open(ETHERNET_PCAP_FILE,'rb') as f:
        pcap =  dpkt.pcap.Reader(f)
        
        # Get the first packet
        timestamp, raw_packet_data = next(iter(pcap))
        
        # Convert timestamp to string format
        timestamp_dt = datetime.fromtimestamp(timestamp)
        
        
    return timestamp_dt, raw_packet_data

@pytest.fixture
def real_ethernet_data() -> dict:
    """Get real ethernet frame data from pcap file."""
    timestamp_dt, packet_bytes = read_first_packet_from_pcap()
    
    return {
        'timestamp': timestamp_dt,
        'data': packet_bytes,
        'description': 'Real ethernet frame from ethernet_test.pcap'
    }
    
@pytest.fixture
def sample_ethernet_data() -> bytes:
    """Fallback synthetic data in case pcap file is missing."""
    return bytes.fromhex('ffffffffffff001122334455080045000014')


@pytest.fixture
def sample_timestamp() -> str:
    """Sample timestamp string."""
    return "14:30:25.123456"

@pytest.fixture
def all_ethernet_pcap_packets() -> list:
    """Get all packets from the pcap file."""
    if not ETHERNET_PCAP_FILE.exists():
        pytest.skip(f"Pcap file not found: {ETHERNET_PCAP_FILE}")
    
    packets = []
    with open(ETHERNET_PCAP_FILE, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        for timestamp, raw_data in pcap:
            timestamp_dt = datetime.fromtimestamp(timestamp)
            
            packets.append({
                'timestamp': timestamp_dt,
                'data': raw_data,
            })
    
    return packets