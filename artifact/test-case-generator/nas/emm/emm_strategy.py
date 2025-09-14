from enum import Enum


class EMMStrategy(Enum):
    BASE = 'BASE'
    APPEND = 'APPEND'
    FLIP = 'FLIP'
    TRUNCATE = 'TRUNCATE'
    TAG = 'TAG'
    ADD = 'ADD'
