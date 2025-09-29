# covert_hunter/features/extractors.py
from abc import ABC, abstractmethod
from typing import Any, Protocol
import numpy as np
from dataclasses import dataclass

# ============================================================================
# PROTOCOL INTERFACE
# ============================================================================

class ParsedPacket(Protocol):
    """Interface that all parsed packets must implement for feature extraction."""
    
    @property
    def timestamp(self) -> Any: ...
    
    @property 
    def packet_id(self) -> int: ...
    
    def get_raw_data(self) -> bytes: ...
    
    def get_layer_type(self) -> str: ...


# ============================================================================
# BASE FEATURE EXTRACTOR
# ============================================================================

class BaseFeatureExtractor(ABC):
    """Abstract base class for all feature extractors."""
    
    @abstractmethod
    def extract_features(self, packet: ParsedPacket) -> dict[str, Any]:
        """Extract features from a parsed packet."""
        pass
    
    @abstractmethod
    def get_feature_names(self) -> list[str]:
        """Return ordered list of feature names."""
        pass
    
    def extract_feature_vector(self, packet: ParsedPacket) -> np.ndarray:
        """Extract features as numpy array."""
        features = self.extract_features(packet)
        feature_names = self.get_feature_names()
        
        return np.array([features.get(name, 0.0) for name in feature_names], dtype=np.float32)


# ============================================================================
# ETHERNET FEATURE EXTRACTOR
# ============================================================================

class EthernetFeatureExtractor(BaseFeatureExtractor):
    """Feature extractor specifically for Ethernet frames."""
    
    def __init__(self, include_payload_analysis: bool = True):
        self.include_payload_analysis = include_payload_analysis
    
    def extract_features(self, ethernet_frame) -> dict[str, Any]:
        """Extract features from EthernetFrame object."""
        
        # Validate input
        if not hasattr(ethernet_frame, 'destination_mac'):
            raise ValueError("Object is not a parsed Ethernet frame")
        
        features = {}
        
        # Basic Ethernet features
        features.update(self._extract_basic_features(ethernet_frame))
        
        # MAC address analysis
        features.update(self._extract_mac_features(ethernet_frame))
        
        # Timing features
        if ethernet_frame.timestamp:
            features.update(self._extract_timing_features(ethernet_frame))
        
        # Payload analysis (optional for performance)
        if self.include_payload_analysis and hasattr(ethernet_frame, '_payload'):
            features.update(self._extract_payload_features(ethernet_frame))
        
        # Protocol hints
        features.update(self._extract_protocol_hints(ethernet_frame))
        
        return features
    
    def _extract_basic_features(self, frame) -> dict[str, Any]:
        """Extract basic Ethernet frame features."""
        import struct
        
        features = {}
        
        # Size features
        total_size = 14 + (len(frame.payload) if frame.payload else 0)
        payload_size = len(frame.payload) if frame.payload else 0
        
        features['total_frame_size'] = total_size
        features['payload_size'] = payload_size
        features['header_to_payload_ratio'] = 14 / max(total_size, 1)
        
        # EtherType analysis
        ethertype_int = struct.unpack('>H', frame.ethernet_type)[0]
        features['ethertype'] = ethertype_int
        features['is_ipv4'] = 1 if ethertype_int == 0x0800 else 0
        features['is_ipv6'] = 1 if ethertype_int == 0x86DD else 0
        features['is_arp'] = 1 if ethertype_int == 0x0806 else 0
        features['is_vlan'] = 1 if ethertype_int == 0x8100 else 0
        
        return features
    
    def _extract_mac_features(self, frame) -> dict[str, Any]:
        """Extract MAC address features."""
        import struct
        
        features = {}
        dst_mac = frame.destination_mac
        src_mac = frame.source_mac
        
        # Address type detection
        features['is_broadcast'] = 1 if dst_mac == b'\xff\xff\xff\xff\xff\xff' else 0
        features['is_multicast'] = 1 if (dst_mac[0] & 0x01) != 0 else 0
        features['is_unicast'] = 1 if not features['is_broadcast'] and not features['is_multicast'] else 0
        
        # OUI analysis
        src_oui = struct.unpack('>I', b'\x00' + src_mac[:3])[0]
        dst_oui = struct.unpack('>I', b'\x00' + dst_mac[:3])[0]
        
        features['src_oui'] = src_oui
        features['dst_oui'] = dst_oui
        features['same_oui'] = 1 if src_oui == dst_oui else 0
        
        return features
    
    def _extract_timing_features(self, frame) -> dict[str, Any]:
        """Extract timing-based features."""
        features = {}
        
        if frame.timestamp:
            features['hour_of_day'] = frame.timestamp.hour
            features['is_business_hours'] = 1 if 9 <= frame.timestamp.hour <= 17 else 0
            features['is_weekend'] = 1 if frame.timestamp.weekday() >= 5 else 0
        
        return features
    
    def _extract_payload_features(self, frame) -> dict[str, Any]:
        """Extract payload analysis features."""
        features = {}
        
        if not frame.payload:
            return features
        
        payload = frame.payload
        
        # Entropy calculation
        features['payload_entropy'] = self._calculate_entropy(payload)
        
        # Statistical features
        features['payload_mean_byte_value'] = np.mean(payload)
        features['payload_std_byte_value'] = np.std(payload)
        features['payload_zero_ratio'] = payload.count(0) / len(payload)
        
        return features
    
    def _extract_protocol_hints(self, frame) -> dict[str, Any]:
        """Peek at higher layers for protocol classification hints."""
        features = {}
        
        if not frame.payload or len(frame.payload) < 20:
            return features
        
        try:
            # Basic IP analysis
            ip_version = (frame.payload[0] >> 4) & 0xF
            features['ip_version'] = ip_version
            
            if ip_version == 4:
                protocol = frame.payload[9]
                features['ip_protocol'] = protocol
                features['is_tcp'] = 1 if protocol == 6 else 0
                features['is_udp'] = 1 if protocol == 17 else 0
                features['is_icmp'] = 1 if protocol == 1 else 0
                
                # Port analysis for TCP/UDP
                if protocol in [6, 17] and len(frame.payload) >= 24:
                    import struct
                    ip_header_len = (frame.payload[0] & 0xF) * 4
                    if len(frame.payload) >= ip_header_len + 4:
                        port_offset = ip_header_len
                        src_port = struct.unpack('>H', frame.payload[port_offset:port_offset+2])[0]
                        dst_port = struct.unpack('>H', frame.payload[port_offset+2:port_offset+4])[0]
                        
                        features['src_port'] = src_port
                        features['dst_port'] = dst_port
                        features['is_dns_port'] = 1 if dst_port == 53 or src_port == 53 else 0
                        features['is_http_port'] = 1 if dst_port == 80 or src_port == 80 else 0
                        features['is_https_port'] = 1 if dst_port == 443 or src_port == 443 else 0
            
        except (IndexError, struct.error):
            pass  # Skip if parsing fails
        
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if len(data) == 0:
            return 0.0
        
        byte_counts = np.bincount(data, minlength=256)
        probabilities = byte_counts[byte_counts > 0] / len(data)
        
        return -np.sum(probabilities * np.log2(probabilities))
    
    def get_feature_names(self) -> List[str]:
        """Return ordered list of feature names."""
        base_features = [
            'total_frame_size', 'payload_size', 'header_to_payload_ratio',
            'ethertype', 'is_ipv4', 'is_ipv6', 'is_arp', 'is_vlan',
            'is_broadcast', 'is_multicast', 'is_unicast',
            'src_oui', 'dst_oui', 'same_oui'
        ]
        
        timing_features = [
            'hour_of_day', 'is_business_hours', 'is_weekend'
        ]
        
        payload_features = [
            'payload_entropy', 'payload_mean_byte_value', 
            'payload_std_byte_value', 'payload_zero_ratio'
        ] if self.include_payload_analysis else []
        
        protocol_features = [
            'ip_version', 'ip_protocol', 'is_tcp', 'is_udp', 'is_icmp',
            'src_port', 'dst_port', 'is_dns_port', 'is_http_port', 'is_https_port'
        ]
        
        return base_features + timing_features + payload_features + protocol_features


# ============================================================================
# FLOW-AWARE FEATURE EXTRACTOR
# ============================================================================

class FlowAwareFeatureExtractor(BaseFeatureExtractor):
    """Feature extractor that considers packet flow context."""
    
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.flow_history = {}  # flow_id -> list of packets
    
    def extract_features(self, packet: ParsedPacket) -> dict[str, Any]:
        """Extract features considering flow context."""
        
        # Extract individual packet features
        individual_extractor = EthernetFeatureExtractor()
        features = individual_extractor.extract_features(packet)
        
        # Add flow-based features
        flow_id = self._get_flow_id(packet)
        flow_features = self._extract_flow_features(packet, flow_id)
        features.update(flow_features)
        
        # Update flow history
        self._update_flow_history(packet, flow_id)
        
        return features
    
    def _get_flow_id(self, packet) -> str:
        """Generate flow identifier."""
        # Simple flow ID based on src/dst
        if hasattr(packet, 'source_mac') and hasattr(packet, 'destination_mac'):
            return f"{packet.source_mac.hex()}_{packet.destination_mac.hex()}"
        return "unknown"
    
    def _extract_flow_features(self, packet, flow_id: str) -> dict[str, Any]:
        """Extract features based on flow history."""
        features = {}
        
        if flow_id not in self.flow_history:
            features['packets_in_flow'] = 0
            features['flow_duration'] = 0.0
            features['avg_packet_size'] = 0.0
            return features
        
        history = self.flow_history[flow_id]
        
        features['packets_in_flow'] = len(history)
        
        if len(history) > 1 and hasattr(packet, 'timestamp'):
            # Calculate flow duration
            first_time = history[0].timestamp if hasattr(history[0], 'timestamp') else None
            current_time = packet.timestamp
            
            if first_time and current_time:
                duration = (current_time - first_time).total_seconds()
                features['flow_duration'] = duration
            else:
                features['flow_duration'] = 0.0
        else:
            features['flow_duration'] = 0.0
        
        # Average packet size in flow
        sizes = []
        for p in history:
            if hasattr(p, '_payload'):
                size = 14 + (len(p._payload) if p._payload else 0)
                sizes.append(size)
        
        features['avg_packet_size'] = np.mean(sizes) if sizes else 0.0
        features['packet_size_std'] = np.std(sizes) if len(sizes) > 1 else 0.0
        
        return features
    
    def _update_flow_history(self, packet, flow_id: str):
        """Update flow history with new packet."""
        if flow_id not in self.flow_history:
            self.flow_history[flow_id] = []
        
        self.flow_history[flow_id].append(packet)
        
        # Keep only recent packets
        if len(self.flow_history[flow_id]) > self.window_size:
            self.flow_history[flow_id] = self.flow_history[flow_id][-self.window_size:]
    
    def get_feature_names(self) -> List[str]:
        """Return feature names including flow features."""
        base_extractor = EthernetFeatureExtractor()
        base_features = base_extractor.get_feature_names()
        
        flow_features = [
            'packets_in_flow', 'flow_duration', 'avg_packet_size', 'packet_size_std'
        ]
        
        return base_features + flow_features


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

def demo_feature_extraction():
    """Demo how to use the feature extractors."""
    
    # Your clean EthernetFrame class stays simple:
    from covert_hunter.protocols.ethernet import EthernetFrame
    
    # Parse packet
    frame = EthernetFrame(timestamp, packet_data)
    
    # Extract features (separate concern)
    extractor = EthernetFeatureExtractor()
    features = extractor.extract_features(frame)
    feature_vector = extractor.extract_feature_vector(frame)
    
    print(f"Extracted {len(features)} features")
    print(f"Feature vector shape: {feature_vector.shape}")
    print(f"DNS port detected: {features.get('is_dns_port', False)}")
    
    # For flow-aware analysis
    flow_extractor = FlowAwareFeatureExtractor()
    flow_features = flow_extractor.extract_features(frame)
    
    print(f"Flow features: {flow_features.get('packets_in_flow', 0)} packets in flow")
