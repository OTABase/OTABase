from enum import Enum



class Fields(Enum):
    """"
    Enum class for the different types of fields that can be targeted by the 
    """
    BIT_STRING = 1
    OCTET_STRING = 2
    INTEGER = 3
    SEQOF = 4