# tests/conftest.py

import pytest
import dpkt
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import Mock
from datetime import datetime

# Path to pcap files
TEST_DATA_DIR = Path(__file__).parent / "test_data"
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
        dt = datetime.fromtimestamp(timestamp)
        timestamp_string = dt.strftime("%H:%M:%S.%f")
        
    return timestamp_string, raw_packet_data

@pytest.fixture
def real_ethernet_data():
    """Get real ethernet frame data from pcap file."""
    timestamp_str, packet_bytes = read_first_packet_from_pcap()
    
    return {
        'timestamp': timestamp_str,
        'data': packet_bytes,
        'description': 'Real ethernet frame from ethernet_test.pcap'
    }
    
@pytest.fixture
def sample_ethernet_data():
    """Fallback synthetic data in case pcap file is missing."""
    return bytes.fromhex('ffffffffffff001122334455080045000014')

