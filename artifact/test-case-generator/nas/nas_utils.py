from pycrate_mobile.NAS import *
from pycrate_mobile import *
from pycrate_core import *

from random import choice, randint
import string
import logging

from utils.logging_config import setup_logging


UINT_TYPES = (base.Uint, base.Uint8, base.Uint16, base.Uint32)


def enable_all_optional_fields(msg: Layer3) -> None:
    """
    Enables all optional fields in a given message.

    Args:
        msg (Layer3): message to enable all optional fields in.

    Returns:    
        None
    """
    for o in msg._opts:
        msg[o[2]._name].set_trans(False)
    return


def random_dic_index(dic: dict):
    """
    Returns a random index from a given dictionary.

    Args:
        dic (dict): dictionary to get random index from.

    Returns:
        any: random key from the given dictionary.
    """

    return choice(list(dic.keys()))


def rand_imsi() -> str:
    """
    Returns a random IMSI composed of 15 digits.

    Returns:
        str: random IMSI.
    """
    length = 15
    alphabet = string.digits
    return ''.join(choice(alphabet) for i in range(length))


def rand_plmn() -> str:
    """
    Returns a random PLMN composed of 6 digits.

    Returns:
        str: random PLMN.
    """
    mcc = str(randint(100, 999))
    mnc = str(randint(10, 999)).zfill(3)
    return mcc + mnc


def rand_tac_list(length: int) -> list[int]:
    """
    Returns a list of random TACs.
    A TAC is a 16-bit integer.
    Args:
        length (int): length of the list to return.

    Returns:
        list[int]: list of random TACs.
    """
    return [randint(0, 2**16 - 1) for _ in range(length)]


def byte_to_bit(c: int) -> int:
    """
    Converts a given number of bytes to bits.

    Args:
        c (int): number of bytes to convert.

    Returns:    
        int: number of bits.
    """
    return c * 8


def get_uint_size(uint: int) -> int:
    """
    Computes the size of a given UINT type in bits.

    Args:
        uint (int): UINT type to get size of.

    Returns:
        int: size of the UINT type in bits.
    """
    match uint:
        case _ if type(uint) is Uint8:
            return byte_to_bit(1)
        case _ if type(uint) is Uint16:
            return byte_to_bit(2)
        case _ if type(uint) is Uint24:
            return byte_to_bit(3)
        case _ if type(uint) is Uint32:
            return byte_to_bit(4)


def get_max_bit_len(msg: IE) -> int:
    """
    Returns the maximum length of a given information element container in bits.

    Args:
        msg (IE): information element to get maximum length of.

    Returns:
        int: maximum length of the information element in bits.
    """
    match type(msg):
        case t if t in (TS24007.Type1TV, TS24007.Type1V):
            return byte_to_bit(2**4)
        # Type 3 has no maximum length but is only used for mandatory fields
        case t if t in (TS24007.Type3V, Type3TV):
            return byte_to_bit(2**16)
        case t if t in (TS24007.Type4TLV, TS24007.Type4LV):
            # Remove 1 because maximum length is 255
            return byte_to_bit(2**8 - 1)
        case t if t in (TS24007.Type6TLVE, TS24007.Type6LVE):
            # TODO Set to actual maximum length, make sure message length can be sent over the air
            # For the moment only use half of the allowed space to fit everything into a message
            return byte_to_bit(2**16 - 1) / 4
        case _:
            return 0


def get_mandatory_bit_len(msg: IE) -> int:
    """
    Returns the mandatory length of a given information element container in bits.

    Args:
        msg (IE): information element to get mandatory length of.
    Returns:
        int: mandatory length of the information element in bits.
    """
    match type(msg):
        case t if t in (TS24007.Type1V, TS24007.Type3V):
            return 0
        case t if t in (TS24007.Type1TV,):
            return 4
        case t if t in (TS24007.Type2, TS24007.Type3TV, TS24007.Type4LV):
            return 8
        case t if t in (TS24007.Type4TLV, TS24007.Type6LVE,):
            return 16
        case t if t in (TS24007.Type6TLVE,):
            return 24
        case _:
            logging.error('Type not found')
            exit(0)


def get_field_metadata_length(msg: IE):
    """ Returns the length of the field metadata (TAG and LENGTH) for a given message

    Args:
        msg (IE): Message to get the metadata length from

    Returns:    
        int: Length of the field metadata
    """
    match type(msg):
        case t if t in (TS24007.Type1V, TS24007.Type3V):
            return 0
        case t if t in (TS24007.Type1TV,):
            return 4 // 8
        case t if t in (TS24007.Type2, TS24007.Type3TV, TS24007.Type4LV):
            return 8 // 8
        case t if t in (TS24007.Type4TLV, TS24007.Type6LVE,):
            return 16 // 8
        case t if t in (TS24007.Type6TLVE,):
            return 24 // 8
        case _:
            logging.error('Type not found')
            exit(0)


def is_optional(msg: IE) -> bool:
    """
    Returns whether a given information element is optional or not.

    Args:
        msg (IE): information element to check.

    Returns:
        bool: True if the information element is optional, False otherwise.
    """
    return type(msg) in (TS24007.Type1TV, Type3TV, TS24007.Type4TLV, TS24007.Type6TLVE, TS24007.Type6LVE)


def save_set_and_get(msg: Element, value):
    """
    Sets the value of a given element, saves it, gets the value and length of the element, and resets the value.
    This is used to get the value in the correct encoding length without modifying the element.
    This is to retrieve the encoding of the element value as it  only is applied once the value is set.


    Args:
        msg (Element): element to set the value of.
        value (any): value to set the element to.

    Returns:
        tuple: tuple containing the new value and length of the element.
    """
    msg.set_val(value)
    new_value = msg.get_val()
    new_length = msg.get_len()
    msg.set_val(None)
    return new_value, new_length
