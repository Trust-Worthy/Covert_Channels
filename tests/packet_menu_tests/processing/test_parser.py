# tests/processing/test_parser.py


import pytest
import numpy as np
from core.processing.parser import Packet_parser

def test_store_and_track_bytes(): 
    
    parser = Packet_parser()