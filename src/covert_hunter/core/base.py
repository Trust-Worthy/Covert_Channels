# src/cover_hunter/core/base.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum


class Threatlevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    
@dataclass
class CovertChannelDetection:
    """Result of covert channel."""
    channel_type: str
    confidence: float
    threat_level: Threatlevel
    description: str