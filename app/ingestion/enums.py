from enum import Enum


class EventType(str, Enum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    CHAT = "CHAT"
    URL = "URL"
    OTHER = "OTHER"
