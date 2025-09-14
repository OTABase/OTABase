from pycrate_mobile.NAS import *
from pycrate_mobile import *
from pycrate_core import *
from pycrate_csn1.csnobj import *

from nas.LCSClientID_gen import generate_LCSClientID_msg
from nas.nas_utils import *
from nas.emm.emm_utils import EMMTypeMTClassesFuzz
from abstract_classes.generator import Generator
from .csn1.csn1_generator import CSN1Generator


from random import choice, randint, randbytes, shuffle
import logging
import time
import os

from utils.logging_config import setup_logging
class EMMGenerator(Generator):
    """ Generator for EMM messages

    """

    # Enable ASN1 generation
    # TS24301_IE._WITH_ASN1 = True

    IGNORE_LIST = ['EMMHeader', 'ESMHeader', 'CPHeader']
    UINT_TYPES = (base.Uint, base.Uint8, base.Uint16, base.Uint32)

    # All Mobile terminated messages
    # EMM Messages
    EMMMT_MSG_LIST = list(EMMTypeMTClassesFuzz.values())
    # NAS Container Messages
    PPSMSCP_LIST = list(PPSMSCPTypeClasses.values())
    # CPUserData
    PPSMSRP_LIST = list(PPSMSRPTypeClasses.values())

    def __init__(self, seed=19, max_bytes=2048):
        super().__init__(seed)

        self.max_bytes = max_bytes
        # Remove 'For Future Use' Value
        if 6 in IDType_dict: 
            del IDType_dict[6]

    def loop_IE(self, msg: Layer3, max_bit_length=byte_to_bit(2048), BUF_LEN=-1):
        """
        Recurively generates values for all the fields in the given root message.

        Args:
            msg (Envelope): _description_
            max_bit_length (int, optional): _description_. Defaults to byte_to_bit(2048).
            BUF_LEN (int, optional): _description_. Defaults to -1.

        Returns:
            final_ie (dict): key-value pairs for all fields in the given message
            available_bits (int): number of remaining available bits from max_bit_length

        """

        # Top level messages
        if type(msg) in list(EMMTypeMTClasses.values()):
            final_ie = {}
            available_bits = max_bit_length
            for m in msg:
                logging.debug("**************************")
                logging.debug(m)
                logging.debug(type(m))

                ie, available_bits = self.loop_IE(m, available_bits)
                logging.debug(
                    f'Used bytes {self.max_bytes - (available_bits // 8)}')
                logging.debug(ie)
                # For each field generate the dict containing its values
                if len(ie) != 0:
                    final_ie |= {m._name: list(ie.values())[0]}

            return final_ie, available_bits

        elif msg._name == 'EMMHeader':
            return {}, max_bit_length - byte_to_bit(2)

        # Ignored messages
        elif msg._name in self.IGNORE_LIST:
            # TODO handle security field in the header field but do not modify message type
            logging.debug('In ignore list')
            # No modification, no bits consumed
            return {}, max_bit_length

        elif hasattr(msg, '_IE_stat'):
            match msg._IE_stat:

                # IE_stat set to None
                case None:
                    logging.debug('None IE stat case')

                    if msg._name == 'CPUserData':
                        # TODO Generate from PPSMSRP
                        return {msg._name: b'\x00\x00\x00\x00'}, max_bit_length - (get_mandatory_bit_len(msg) + byte_to_bit(4))

                    # TODO Connect to ESM generator
                    # Generate ESM message
                    if msg._name == 'ESMContainer':
                        # Empty message, consumes the mandatory fields and 3 bytes by default for correct decoding
                        return {msg._name: b'\x00\x00\x00'}, max_bit_length - (get_mandatory_bit_len(msg) + byte_to_bit(3))

                    # Generate NAS message, currently only SMS

                    # TODO Extract this
                    if msg._name == 'NASContainer':
                        NAS_CONTAINER_MAX_LEN = 252
                        logging.debug('NAS container')
                        logging.debug(msg._name)
                        logging.debug(type(msg))

                        p = choice(self.PPSMSCP_LIST)
                        logging.debug(p)
                        ie, _ = self.loop_IE(
                            p(), max_bit_length=NAS_CONTAINER_MAX_LEN * 8)

                        logging.debug(ie)
                        nas_msg = p(val=ie[p()._name])

                        assert len(nas_msg.to_bytes()
                                   ) < NAS_CONTAINER_MAX_LEN
                        logging.debug('End of NAS container')
                        return {msg._name: nas_msg.to_bytes()}, max_bit_length - (get_mandatory_bit_len(msg) + byte_to_bit(len(nas_msg.to_bytes())))

                    else:
                        logging.debug('No IE found')
                        logging.debug(msg._name)
                        logging.debug(type(msg))

                        max_bit_length -= get_mandatory_bit_len(msg)
                        m = msg['V']

                        available_bits = 0
                        # Optional fields take as much space as they can up to max_bit_length if possible or up to their field type max length
                        if is_optional(msg):
                            available_bits = min(
                                max_bit_length, int(get_max_bit_len(msg)))
                        else:
                            # Mandatory fields will always have enough bits
                            available_bits = int(get_max_bit_len(msg))

                        ie, remaining_bits = self.loop_IE(m, available_bits)

                        logging.debug(f'Remaining bytes {remaining_bits // 8}')
                        return {msg._name: list(ie.values())[0]}, max_bit_length - (available_bits - remaining_bits)

                # Unwrap the IE definition
                case _:
                    logging.debug('IE with envelop')
                    logging.debug(msg)
                    # Remove the length taken by size and tag fields
                    max_bit_length -= get_mandatory_bit_len(msg)
                    available_bits = 0
                    # Optional fields take as much space as they can up to max_bit_length if possible or up to their field type max length
                    if is_optional(msg):
                        available_bits = min(
                            max_bit_length, get_max_bit_len(msg))
                    else:
                        # Mandatory fields will always have enough bits
                        available_bits = get_max_bit_len(msg)
                    logging.debug(f'AVL BYTES {available_bits // 8}')

                    ie, remaining_bits = self.loop_IE(
                        msg._IE_stat, available_bits)
                    logging.debug(
                        f'Consumed bytes {(available_bits - remaining_bits) // 8}')
                    logging.debug(ie)
                    logging.debug(msg._name)
                    return {msg._name: list(ie.values())[0]}, max_bit_length - (available_bits - remaining_bits)

        else:
            match msg:

                # CSN1List
                case msg if type(msg) is CSN1List:
                    csn1_generator = CSN1Generator(m)
                    logging.debug('CSN1List')
                    return {msg._name: csn1_generator.get_next_packet()}

                # EPSID case
                case msg if type(msg) is TS24301_IE.EPSID:

                    logging.debug('EPSID')

                    available_bits = max_bit_length
                    random_EPSID_type = random_dic_index(EPSIDType_dict)
                    # type is IDTYPE_GUTI: ident must be a 4-tuple (PLMN -string of digits-,
                    # MMEGroupID -uint16-, MMECode -uint8-, MTMSI -uint32-)
                    if random_EPSID_type is IDTYPE_GUTI:
                        MAX_BYTE_LENGTH = 13 - 2  # Remove Tag and length field
                        MIN_BYTE_LENGTH = MAX_BYTE_LENGTH

                        tup = (None, randint(0, 2**16 - 1),
                               randint(0, 2**8 - 1), randint(0, 2**32 - 1))
                        msg.encode(random_EPSID_type, tup)
                        new_ies = {}
                        for i in msg:
                            ie, available_bits = self.loop_IE(
                                i, available_bits)
                            new_ies |= ie

                        # Do not change the type here for correctness
                        new_ies['Type'] = random_EPSID_type
                        return {msg._name: {'type': IDTYPE_GUTI, 'ident':  (new_ies['PLMN'], new_ies['MMEGroupID'], new_ies['MMECode'], new_ies['MTMSI'])}}, available_bits

                    else:
                        msg.encode(random_EPSID_type, rand_imsi())
                        new_ies = {}
                        for i in msg:
                            ie, available_bits = self.loop_IE(
                                i, available_bits)
                            new_ies |= ie

                        # Do not change the type here for correctness
                        new_ies['Type'] = random_EPSID_type

                        return {msg._name: {'type': random_EPSID_type, 'ident':  rand_imsi()}}, available_bits

                # ID
                case msg if type(msg) is TS24008_IE.ID:
                    logging.debug('ID')

                    available_bits = max_bit_length

                    random_type = random_dic_index(IDType_dict)

                    match random_type:
                        # if type is IDTYPE_TMSI: ident must be an uint32
                        case TS24008_IE.IDTYPE_TMSI:
                            return {msg._name: {'type': TS24008_IE.IDTYPE_TMSI, 'ident': randint(0, 2**32 - 1)}}, available_bits - byte_to_bit(5)
                        # if type is IDTYPE_IMSI, IDTYPE_IMEI or IDTYPE_IMEISV: ident must be a
                        # string of digits
                        case TS24008_IE.IDTYPE_IMSI | TS24008_IE.IDTYPE_IMEI | TS24008_IE.IDTYPE_IMEISV:
                            # Considers the size of the IMSI
                            return {msg._name: {'type': random_type, 'ident': rand_imsi()}}, available_bits - byte_to_bit(8)
                        # if type is IDTYPE_TMGI: ident must be a 3-tuple (MBMSServID -uint24-,
                        # PLMN -string of digits- or None, MBMSSessID -uint8- or None)
                        case TS24008_IE.IDTYPE_TMGI:
                            return {msg._name: {'type': random_type, 'ident': (randint(0, 2**24 - 1), rand_plmn(), randint(0, 2**8 - 1))}}, available_bits - byte_to_bit(8)
                        case TS24008_IE.IDTYPE_NONE:
                            return {msg._name: {'type': random_type, 'ident': None}}, available_bits - byte_to_bit(1)

                # TAI List
                case msg if type(msg) is TS24301_IE.TAIList:
                    logging.debug('TAIList')

                    # TODO Get those values from BASESPEC
                    MAX_BYTE_SIZE = 98 - 2  # Remove Tag and length field
                    MIN_BYTE_SIZE = 8 - 2
                    MAX_TAI = 16
                    TAI_COUNT = 0

                    PREV_LENGTH = 0
                    CURR_LENGTH = 0  # TAG and LEN are already accounted for
                    target_length = randint(MIN_BYTE_SIZE, MAX_BYTE_SIZE)

                    # Number of TAI elements should not exceed CURR_LENGTH of MAX_BYTE_SIZE
                    TAIList_list = []
                    TAIValues_type2 = {}
                    last_added_type = None
                    while True:
                        # val={'TAIList': [{'Type' : 0, 'Num' : 1, 'PLMN' : '345345', 'TACValues' : (3453,4353)}, {'Type' : 0, 'Num' : 1, 'PLMN' : '43535'}]})
                        TAI_type = random_dic_index(
                            TS24301_IE._PTAIListType_dict)

                        plmn = rand_plmn()
                        # 3 types of different TAIlists in the message
                        entry = {'Type': TAI_type}
                        match TAI_type:

                            # Type : 0 (list of TACs belonging to one PLMN, with non-consecutive TAC values)
                            case 0:
                                logging.debug('TAI type 0')
                                n_elem = randint(1, 8)
                                PREV_LENGTH = CURR_LENGTH
                                CURR_LENGTH += 2 * n_elem + 4
                                tacs = rand_tac_list(n_elem)
                                PTAI_entry = {'PLMN': plmn,
                                              'TACs': tacs}
                                TAI_COUNT += 1
                                last_added_type = 0
                                entry['PTAI'] = PTAI_entry
                                TAIList_list.append(entry)

                            # Type : 1 (list of TACs belonging to one PLMN, with consecutive TAC values)
                            case 1:
                                logging.debug('TAI type 1')
                                tac = rand_tac_list(1)[0]
                                # 5 bits but MSB should stay 0, i.e 4 bits range
                                n_elem = randint(0, 2**4 - 1)
                                PTAI_entry = {'Num': n_elem,
                                              'PLMN': plmn, 'TAC1': tac}
                                PREV_LENGTH = CURR_LENGTH
                                CURR_LENGTH += 6
                                TAI_COUNT += 1
                                last_added_type = 1
                                entry['PTAI'] = PTAI_entry
                                TAIList_list.append(entry)

                            # Type : 2 (list of TAIs belonging to different PLMNs)
                            case 2:
                                logging.debug('TAI type 2')
                                tac = rand_tac_list(1)[0]

                                # Type 2 list supports up to 16 entries
                                if len(TAIValues_type2) == 16:
                                    TAIValues_type2 = {}
                                type2_entry = {
                                    len(TAIValues_type2): (plmn, tac)}
                                TAIValues_type2 |= type2_entry
                                TAI_COUNT += 1
                                PREV_LENGTH = CURR_LENGTH
                                CURR_LENGTH += 5

                                if len(TAIValues_type2) == 1:
                                    CURR_LENGTH += 1
                                    TAIList_list.append(
                                        entry | {'PTAI': {'TAIs': TAIValues_type2}})
                                last_added_type = 2
                        # As soon as the current length is equal to length or the max number of TAI element is reached, stop
                        if CURR_LENGTH == target_length or TAI_COUNT == MAX_TAI:
                            break

                        # Remove last added value and return
                        if CURR_LENGTH > target_length and (PREV_LENGTH >= MIN_BYTE_SIZE):
                            if last_added_type == 2:
                                # Find last type 2 in TAIList_list and pop the last item
                                for i in range(len(TAIList_list) - 1, -1, -1):
                                    if TAIList_list[i]['Type'] == 2:
                                        if len(TAIList_list[i]['PTAI']['TAIs']) == 1:

                                            # Remove the whole type 2 entry
                                            TAIList_list.pop(i)
                                            logging.debug(
                                                'Removing type 2 entry')
                                        else:
                                            TAIList_list[i]['PTAI']['TAIs'].popitem(
                                            )
                                            logging.debug(
                                                'Removing type 2 item')
                                        break
                                logging.debug('Poping item from type 2')
                            else:
                                # Type 0 and 1 can be popped directly from the list
                                TAIList_list.pop()
                                logging.debug('Removing type 0 or 1 entry')

                            CURR_LENGTH = PREV_LENGTH
                            break

                    assert CURR_LENGTH >= MIN_BYTE_SIZE

                    logging.debug(
                        'TAIList Target length was %d', target_length)
                    logging.debug('TAIList Final length is %d', CURR_LENGTH)
                    return {msg._name: TAIList_list}, max_bit_length - byte_to_bit(CURR_LENGTH)

                # Network Name
                case msg if type(msg) is TS24008_IE.NetworkName:
                    # max length is the max size of a Type4 Field
                    available_bits = max_bit_length
                    new_ie = {}
                    for field in msg[:-1]:
                        ie, available_bits = self.loop_IE(
                            field, available_bits)
                        new_ie |= ie

                    ie, available_bits = self.loop_IE(msg[-1], available_bits)
                    new_ie |= ie
                    return {msg._name: new_ie}, available_bits

                # Timezone
                case msg if type(msg) is TS24008_IE.TimeZone:
                    available_bits = max_bit_length
                    logging.debug('Timezone field')
                    # Encode random data to generate the fields
                    # UTC−12:00 to UTC+14:00, can generate by 30 mins gaps
                    msg.encode(randint(-24, 28) / 2)
                    new_ies = {}
                    for m in msg:
                        new_ies |= {m._name: m.get_val()}

                    return {msg._name: new_ies}, available_bits - byte_to_bit(1)

                # SCTS
                case msg if type(msg) is TS24008_IE._TP_SCTS_Comp:
                    logging.debug('SCTS')
                    match msg._name:
                        case 'Year':
                            msg.encode(randint(0, 99))
                        case 'Month':
                            msg.encode(randint(1, 12))
                        # Assume 28 days for each month for correctness
                        case 'Day':
                            msg.encode(randint(1, 28))
                        case 'Hour':
                            msg.encode(randint(0, 23))
                        case 'Min':
                            msg.encode(randint(0, 59))
                        case 'Sec':
                            msg.encode(randint(0, 59))

                    return {msg._name: msg.get_val()}, max_bit_length - byte_to_bit(1)

                # PLMN List : 24 008, 10.5.1.13
                case m if type(m) is TS24008_IE.PLMNList:
                    logging.debug('PLMNLIST')
                    available_bits = max_bit_length
                    ELEMENT_BYTE_SIZE = 3
                    MIN_BYTE_LENGTH = 3
                    MAX_BYTE_LENGTH = 45
                   
                    n_elem = randint(int(MIN_BYTE_LENGTH / ELEMENT_BYTE_SIZE),
                                     int(MAX_BYTE_LENGTH / ELEMENT_BYTE_SIZE))
                    new_ie = {}
                    for i in range(n_elem):
                        new_ie |= {i: rand_plmn()}

                    return {m._name: new_ie}, available_bits - byte_to_bit(ELEMENT_BYTE_SIZE * n_elem)

                # Emergency Number List : TS 24.008, 10.5.3.13
                case m if type(m) is TS24008_IE.EmergNumList:
                    logging.debug('Emergency number list')

                    available_bits = max_bit_length
                    # At least 1 byte in the number buffer
                    ELEMENT_MIN_SIZE = 3
                    MIN_BYTE_LENGTH = 3
                    MAX_BYTE_LENGTH = 48
                    # Make sure to use buffer space inside each element
                    BYTES_TO_USE = randint(MIN_BYTE_LENGTH, MAX_BYTE_LENGTH)

                    n_elem = randint(1, BYTES_TO_USE // ELEMENT_MIN_SIZE)
                    bytes_per_elem = BYTES_TO_USE // n_elem
                    remainder = BYTES_TO_USE % n_elem

                    assert BYTES_TO_USE - \
                        (bytes_per_elem * n_elem + remainder) == 0
                    new_ie = {}
                    for i in range(n_elem):

                        elem_length = bytes_per_elem
                        # Last Element consumes all the remaining bytes
                        if i == n_elem - 1:
                            elem_length += remainder

                        ie, remaining_bits = self.loop_IE(
                            m._GEN, byte_to_bit(elem_length))
                        assert remaining_bits == 0
                        ie = list(ie.values())[0]
                        # Let length parameter be set automatically to BCD Buffer size
                        del ie['Len']
                        new_ie |= {i: ie}

                    # Shuffle the array order to remove remaing_bytes biased selection
                    values = list(new_ie.values())
                    shuffle(values)
                    new_ie = {k: v for k, v in zip(new_ie.keys(), values)}
                    return {m._name: new_ie}, available_bits - byte_to_bit(BYTES_TO_USE)

                # Extended Emergency Number List
                case msg if type(msg) is TS24301_IE.ExtEmergNumList:
                    available_bits = max_bit_length

                    logging.debug('Extended Emergency Number')
                    final_ie = {}

                    # First two fields (1 byte)
                    for field in msg[:-1]:
                        ie, available_bits = self.loop_IE(
                            field, available_bits)
                        final_ie |= ie

                    AVLB_BYTES = available_bits // 8

                    # The two bytes each for a length fields of two empty bufs
                    ELEMENT_MIN_SIZE = 2
                    assert AVLB_BYTES > ELEMENT_MIN_SIZE

                    BYTES_TO_USE = randint(ELEMENT_MIN_SIZE, AVLB_BYTES)
                    # TODO Unconstrain size here
                    BYTES_TO_USE = 100  # For the moment keep the size constraint
                    n_elem = randint(1, BYTES_TO_USE // ELEMENT_MIN_SIZE)

                    # Remove the two length bytes
                    bytes_per_elem = BYTES_TO_USE // n_elem - 2
                    remainders = BYTES_TO_USE % n_elem

                    array_ie = {}
                    for i in range(n_elem):
                        # Last Element consumes all the remaining bytes
                        if i == n_elem - 1:
                            bytes_per_elem += remainders

                        first_elem = True
                        buf_len = randint(0, bytes_per_elem)

                        elem_ie = {}
                        for field in msg[-1]._tmpl:
                            # Ignore the length fields
                            if type(field) is not Uint8:

                                ie, remaining_bits = self.loop_IE(
                                    field, byte_to_bit(buf_len))

                                # Buffers should consumer everything
                                assert remaining_bits == 0
                                elem_ie |= ie

                                if first_elem:
                                    first_elem = False
                                    buf_len = bytes_per_elem - buf_len

                        array_ie[i] = elem_ie

                    final_ie[msg[-1]._name] = array_ie

                    return {msg._name: final_ie}, available_bits - byte_to_bit(BYTES_TO_USE)

                # Cipher Key Data
                case msg if type(msg) is TS24301_EMM.CipherKeyData:
                    logging.debug('Cipher Key Data')
                    available_bits = max_bit_length
                    # TODO Get from BASESPEC and use
                    MAX_BYTE_LENGTH = 2291 - 3  # Remove tag and length field length
                    MIN_BYTE_LENGTH = 35 - 3
                    MAX_NUM_CIPHER_DATASET = 16

                    n_elem = randint(1, MAX_NUM_CIPHER_DATASET)
                    seq_ie = ()
                    for i in range(n_elem):
                        elem_ie = {}
                        for field in msg._GEN:
                            if field._name == 'C0':
                                ie, available_bits = self.loop_IE(
                                    field, available_bits, elem_ie['C0Len'])
                            else:
                                ie, available_bits = self.loop_IE(
                                    field, available_bits)

                            elem_ie |= ie
                        # Let it be set automatically
                        del elem_ie['TAIListLen']
                        seq_ie += (elem_ie,)

                    return {msg._name: seq_ie}, available_bits

                # BCD Number
                case msg if issubclass(type(msg), TS24008_IE.BCDNumber):
                    logging.debug('BCD number')
                    logging.debug(msg)

                    new_ie = {}
                    available_bits = max_bit_length

                    for field in msg[:-1]:
                        ie, available_bits = self.loop_IE(
                            field, available_bits)
                        logging.debug(f'Remaining bits are {available_bits}')
                        new_ie |= ie

                    # Octet 3a is present if the first bit is set to 1, this has probability 1/2
                    skip_3a = new_ie['Ext'] == 1
                    if skip_3a:
                        del new_ie['Ext3a']
                        available_bits += 8

                    MIN_BYTE_LENGTH = 0
                    MAX_BYTE_LENGTH = 4

                    byte_length = randint(MIN_BYTE_LENGTH, MAX_BYTE_LENGTH)
                    assert max_bit_length >= byte_to_bit(byte_length)
                    buf_ie, remaining_bits = self.loop_IE(
                        msg[-1], byte_to_bit(byte_length))

                    # All length consumed
                    assert remaining_bits == 0
                    new_ie |= buf_ie

                    return {msg._name: new_ie}, available_bits - byte_to_bit(byte_length)

                # TODO Add LCSClientID generation with length constraint
                case msg if msg._name == 'LCS-ClientID':
                    packet, length, _, _ = generate_LCSClientID_msg()
                    return {msg._name: packet}, max_bit_length - byte_to_bit(length)

                # Uint case
                case msg if any(type(msg) is i or issubclass(type(msg), i) for i in self.UINT_TYPES):
                    logging.debug("Got Uint")
                    logging.debug(msg._name)

                    field_bit_size = msg.get_bl()
                    remaining_bits = max_bit_length - field_bit_size
                    # ignore spare values
                    if msg._name == 'spare':
                        return {msg._name: 0}, remaining_bits

                    logging.debug(f'Old value : {msg.get_val()}')

                    # There is a dictionnary of valid values
                    if msg._dic is not None:
                        new_value = random_dic_index(msg._dic)
                        new_value, _ = save_set_and_get(msg, new_value)
                        logging.debug(f'New value : {new_value}')

                        return {msg._name: new_value}, remaining_bits

                    # Generate a random number of the correct bit length
                    else:
                        logging.debug(f'Integer bit length : {msg._bl}')
                        new_value = randint(0, 2**msg._bl - 1)
                        new_value, _ = save_set_and_get(msg, new_value)
                        logging.debug(f'New value : {new_value}')

                        return {msg._name: new_value}, remaining_bits

                # BCD buffer
                case msg if issubclass(type(msg), BufBCD):

                    logging.debug('BCD buffer')

                    alphabet = list(msg._chars)
                    length = msg.get_len()
                    if msg._bl is None:
                        logging.debug('BCD Buffer has None bit length')
                        length = max_bit_length // 8

                    logging.debug(f'BCD buffer length is {length}')

                    # TODO Figure out why the length is not affected wrongly here
                    # i.e why is safe_set_and_get not need here
                    # Use the alphabet to correctly generate the values
                    msg.encode(''.join(choice(alphabet)
                                       for i in range(2 * length)))

                    assert len(msg.get_val()) == length

                    return {msg._name: msg.get_val()}, 0

                # Buffer or any kind of buffer subclass
                case msg if type(msg) is base.Buf or issubclass(type(msg), base.Buf):
                    logging.debug(
                        f"Got Buffer {msg.get_len()}, {msg.get_val()}")

                    if msg.get_bl() % 8 != 0:
                        logging.error('Buffer size is not byte aligned')
                        exit(0)
                    # Spare buffers have default value
                    if msg._name == 'spare':
                        return {}

                    data = b''
                    assert msg.get_len() * 8 == msg.get_bl()
                    # Check if there is a fixed size of data
                    if msg.get_len() == 0:

                        if BUF_LEN != -1:
                            logging.debug(
                                f'Data length passed by BUF_LEN {BUF_LEN}')
                            data = randbytes(BUF_LEN)
                        # Length provided by previous field
                        else:
                            # Use Max available length
                            # TODO Handle case where the Buffer is in one of the middle field. Should not consume all bytes
                            logging.debug(
                                f'Data length from max_bit_length : {max_bit_length}')
                            data = randbytes(max_bit_length // 8)
                    else:
                        logging.debug('Data length from buffer')
                        data = randbytes(msg.get_len())

                    logging.debug(f'Buffer has length {len(data)}')

                    # Get correct value encoding
                    data, length = save_set_and_get(msg, data)
                    return {msg._name: data}, max_bit_length - byte_to_bit(length)

                # Array
                case msg if issubclass(type(msg), Array):
                    logging.debug('Array subclass no IE')
                    logging.debug(msg)

                    final_ie = {}
                    # All Array cases are handeled seperatly
                    if type(msg._GEN) is Atom:
                        return {msg._name: self.loop_IE(msg._tmpl)}

                    logging.error('Array Case not handled seperatly')
                    exit(0)

                # Envelope
                case msg if issubclass(type(msg), Envelope):
                    logging.debug('In envelope case IE')

                    new_ies = {}
                    logging.debug(msg._name)
                    available_bits = max_bit_length

                    for m in msg:
                        ie, available_bits = self.loop_IE(m, available_bits)
                        logging.debug(f'Remaining bits are {available_bits}')
                        new_ies |= ie
                    logging.debug('Final envelope IE')
                    logging.debug(new_ies)

                    return {msg._name: new_ies}, available_bits

                case _:
                    logging.error('No match')
                    exit(0)

    def get_packet_generator(self):
        """
        Implements a packet generator for EMM messages.
        If all packets are generated, the generator will return None.

        Yields:
            tuple: (message_key_values (dict), message_type (Envelope), optional_fields (list))
        """
        while(True):
            for EMMMT_msg_type in EMMGenerator.EMMMT_MSG_LIST:

                start_time = time.time()
                logging.debug(EMMMT_msg_type)
                msg = EMMMT_msg_type()
                enable_all_optional_fields(msg)

                logging.debug(EMMMT_msg_type)
                logging.debug('-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-')

                # Generate IE values
                ie, remaining_bits = self.loop_IE(msg)

                rand_msg = EMMMT_msg_type(val=ie)

                used_bytes = 2048 - (remaining_bits // 8)

                assert len(rand_msg.to_bytes()) == used_bytes

                logging.debug('Decoding .....')
                Msg, err = parse_NASLTE_MT(
                    unhexlify(rand_msg.to_bytes().hex()))
                assert Msg.to_bytes() == rand_msg.to_bytes()

                # TODO These error codes correspond to NAS and ESM container values being invalid
                if err != 0 and err != 97:
                    logging.error(err)
                    logging.error('NOT GOOD')
                    exit(0)

                if Msg is None:
                    logging.error('Decoded messsage is None')
                    exit(0)

                end_time = time.time()

                logging.debug(f'Time taken : {end_time - start_time}')
            
                yield (Msg.to_bytes() ,ie, EMMMT_msg_type, list(map(lambda x: x[2]._name, msg._opts)))

            logging.debug('Generator cycle ended')

    
            yield None
