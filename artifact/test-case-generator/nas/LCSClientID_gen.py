from pycrate_asn1dir import MAP
from pycrate_asn1dir.MAP import *
import random
import os
import sys

import logging
import string

from utils.logging_config import setup_logging

ENABLE_OPTIONAL = True


def loop_IE(bb, curr_path=[]) -> tuple:
    """
    Recursively generate a LCSClientID message

    Args:
        bb (object): The current ASN.1 object.
        curr_path (list): The path to the current ASN.1 object.

    Returns:    
        result (bytes): The generated LCSClientID message.
        mutation_paths (list): The list of paths to the mutated fields.
        optional_paths (list): The list of paths to the optional fields.

    """

    if (bb.TYPE == 'NULL'):
        return 0, [], []

    if (bb.TYPE == 'SEQUENCE'):
        logging.debug('SEQUENCE')
        logging.debug(f'Current path is {curr_path}')
        logging.debug(bb._name)
        logging.debug(f'Sequence is optional : {bb._opt}')
        logging.debug(bb._root)

        # check if the sequence is empty
        if (bb == {}):
            # return empty dictionary or nothing
            # return {}
            return
        one_ie = {}

        optional_paths = []
        tot_optional_paths = []
        tot_mutation_paths = []

        items = [t[0] for t in list(bb._cont.items())]
        # Optional fields
        if bb._opt:
            logging.debug(f'Sequence is optional : {bb._opt}')
            optional_paths.append(curr_path)

        for ie_name in items:

            # Ignores all the optional fields
            if ie_name in bb._root_mand or ENABLE_OPTIONAL:
                gen, rec_mutation_paths, rec_optional_paths = loop_IE(
                    bb._cont[ie_name], [*curr_path, ie_name])
                one_ie[ie_name] = gen

                tot_optional_paths += rec_optional_paths
                tot_mutation_paths += rec_mutation_paths

                logging.debug(tot_mutation_paths)

        return one_ie, [l for l in tot_mutation_paths if l], optional_paths + tot_optional_paths

    if (bb.TYPE == 'CHOICE'):
        logging.debug('CHOICE')
        logging.debug(f'Current path is {curr_path}')
        logging.debug(bb._name)
        logging.debug(bb._root)

        # Selects next field, ignores all fields in IGNORE
        options = list(bb._cont.keys())
        logging.debug(options)
        # weights = list(map(lambda x: x.weight, list(bb._cont.values())))

        logging.debug(bb._cont)

        optional_paths = []
        if bb._opt:
            optional_paths.append(curr_path)

        choice_ie_num = len(bb._root)
        # Among the choice, include the random one.
        rand_ie = random.randint(0, choice_ie_num-1)

        # Exclude spare values for now.
        while ('spare' in bb._root[rand_ie]):
            rand_ie = random.randint(0, choice_ie_num-1)

        value = bb._root[rand_ie]
        gen, rec_mutation_paths, rec_optional_paths = loop_IE(
            bb._cont[value], [*curr_path,  value])

        return (value, gen), [p for p in rec_mutation_paths if p], optional_paths + rec_optional_paths

    if (bb.TYPE == 'INTEGER'):

        # Default value is replaced here
        # one_ie = bb._const_val.root[0]
        ie_range = bb._const_val.root[0]
        ie_lb = ie_range.lb
        ie_ub = ie_range.ub
        optional_paths = []
        if bb._opt:
            logging.debug('Optional Integer')
            optional_paths.append(curr_path)
        # pick random value between lb and ub
        return random.randint(ie_lb, ie_ub), [], optional_paths

    if (bb.TYPE == 'ENUMERATED'):
        logging.debug('ENUMERATED')
        logging.debug(bb._root)
        optional_paths = []
        if bb._opt:
            optional_paths.append(curr_path)

        return random.choice(bb._root), [], optional_paths

    if (bb.TYPE == 'BOOLEAN'):
        logging.debug('BOOLEAN')
        logging.debug(bb._root)
        optional_paths = []
        if bb._opt:
            optional_paths.append(curr_path)
        return random.choice([True, False]), [], optional_paths

    if (bb.TYPE == 'OCTET STRING'):
        logging.debug('OCTET STRING')

        # The octet string has a format
        logging.debug(bb._root)
        logging.debug(bb._name)

        optional_paths = []
        if bb._opt:
            logging.debug('OCTET STRING IS OPTIONAL')
            optional_paths.append(curr_path)

        # Recursif field
        if "condReconfigurationToApply-r16" == bb._name:
            return b'', [], optional_paths

        if bb._const_cont is not None:

            logging.debug(bb._const_cont.get_type_list())
            logging.debug('Found OCTET String with format')
            exit(0)
            logging.debug('OCTET string with sepific format')
            test_1 = RRCLTE.GLOBAL.MOD['EUTRA-RRC-Definitions'][bb._const_cont.get_type_list()[
                0]]

            ie, rec_mutation_paths, rec_optional_paths = loop_IE(
                test_1, curr_path)
            logging.debug(ie)
            logging.debug(bb._name)

            embedded_mutation_paths = []
            # Insert '*' to find where the container starts
            for m in rec_mutation_paths:
                embedded_mutation_paths.append(
                    curr_path + ['*', bb._const_cont.get_type_list()[0]] + m[len(curr_path):])

            for o in rec_optional_paths:
                optional_paths.append(
                    curr_path + ['*', bb._const_cont.get_type_list()[0]] + o[len(curr_path):])

            test_1.set_val(ie)

            return bytes.fromhex(test_1.to_uper().hex()), [curr_path] + embedded_mutation_paths, optional_paths

        mutation_path = curr_path
        # Length is bound
        if (bb._const_sz != None):
            oct_str_len = random.randint(bb._const_sz.lb, bb._const_sz.ub)
            # Length can take a single value, no need to mutate
            if bb._const_sz.lb == bb._const_sz.ub:
                mutation_path = []
        else:
            # Choose long enough content to uniquely identify it
            oct_str_len = 32
        logging.debug(optional_paths)
        return os.urandom(oct_str_len), [mutation_path], optional_paths

    if (bb.TYPE == 'BIT STRING'):

        logging.debug('BIT STRING')

        optional_paths = []
        if bb._opt:
            optional_paths.append(curr_path)

        if bb._const_cont is not None:
            logging.debug('Found not None continuation for BIT STRING')
            exit(0)

        mutation_path = curr_path

        if (bb._const_sz != None):
            logging.debug(f'Upper bound {bb._const_sz.ub}')
            logging.debug(f'Lower bound {bb._const_sz.lb}')
            bit_str_len = random.randint(bb._const_sz.lb, bb._const_sz.ub)

            # Length can take a single value, no need to mutate
            if bb._const_sz.lb == bb._const_sz.ub:
                mutation_path = []

        else:
            # Choose long enough content to uniquely identify it
            bit_str_len = 64

        logging.debug(bb._root)
        logging.debug(bb.get_root_path())

        # codebookSubsetRestriction-r10 에는 length 가 안정해져있음. P-C-AndCBSR 에도.
        return (random.getrandbits(bit_str_len), bit_str_len), [mutation_path], optional_paths

    if (bb.TYPE == 'SEQUENCE OF'):
        logging.debug('SEQUENCE OF')
        optional_paths = []
        if bb._opt:
            optional_paths.append(curr_path)

        temp = []
        mutation_paths = []

        n_elem = random.randint(bb._const_sz.lb, bb._const_sz.ub)

        # Generate the smallest message possible
        n_elem = bb._const_sz.lb
        logging.debug(f'Number of elements : {n_elem}')

        for i in range(n_elem):
            gen, rec_mutation_paths, rec_optional_paths = loop_IE(
                bb._cont, [*curr_path, i])  # [*curr_path, bb._name, i] Old value

            temp.append(gen)
            mutation_paths += rec_mutation_paths
            optional_paths += rec_optional_paths
            # exit(0)

        logging.debug(mutation_paths)
        logging.debug(optional_paths)

        return temp, [p for p in mutation_paths if p], optional_paths

    if bb.TYPE == 'OBJECT IDENTIFIER':
        # The length of the Object Identifier shall not exceed 16 octets
        #  the number of components of the Object Identifier shall not exceed 16
        length = random.randint(2, 16)
        OID = tuple(random.randint(0, 2**(16*8)) for i in range(length))
        optional_paths = []
        if bb._opt:
            optional_paths.append(curr_path)

        return OID, [], optional_paths

    # TODO Randomize using all values from _ASN1ObjBasicLUT (Need to implement all the string formats)
    if bb.TYPE == 'OPEN_TYPE':
        logging.debug('open type')

        # logging.debug(bb._from_per())

        constraints = bb._get_const_tr()
        optional_paths = []
        logging.debug(type(bb))
        logging.debug(bb._get_val_obj(TYPE_BOOL))

        bb.set_val((TYPE_NULL, 0))
        logging.debug(bb._tag)

        logging.debug(bb._get_const_tr())

        if bb._opt:
            optional_paths.append(curr_path)

        if len(constraints) == 0:
            logging.debug(bb._parent.__dir__())
            [TYPE_BOOL, TYPE_ANY, TYPE_BIT_STR, TYPE_CHAR_STR,
                TYPE_BYTES, TYPE_OCT_STR, TYPE_INT]
            return (TYPE_BOOL, True), [], optional_paths
        else:
            logging.debug('Constraints not empty')
            exit(0)


# Returns bytes corresponding to a LCS_ClientID packet (Fully randomized)
def generate_LCSClientID_packet_test():
    """
    Generate a random LCSClientID message

    Returns:
        result (bytes): The generated LCSClientID message.
    """

    while (True):
        bb = MAP.MAP_LCS_DataTypes.LCS_ClientID
        fuzz_result = MAP.MAP_LCS_DataTypes.LCS_ClientID
        error_decoding_list = []

        total_try = 0
        total_except = 0

        result = loop_IE(bb)
        try:
            fuzz_result.set_val(result)
            total_try += 1
        except Exception as e:
            logging.debug("error: ", e)
            total_except += 1
            exit(0)

        logging.debug(fuzz_result.to_uper())

        try:
            fuzz_result._safechk_val(fuzz_result._val)
        except Exception as err:
            logging.debug("Failed passing safe check")
            logging.debug(fuzz_result.to_uper().hex())
            exit(0)
        logging.debug('out of ')

        # Collect invalid format by encoding and decoding
        try:
            RCR_1 = MAP.MAP_LCS_DataTypes.LCS_ClientID
            RCR_1.from_uper(fuzz_result.to_uper())
        except Exception as err:
            logging.debug("Decoding failed")
            logging.debug(fuzz_result._val)
            logging.debug(fuzz_result.to_uper().hex())
            logging.debug(err)
            error_decoding_list.append(fuzz_result.to_uper().hex())
            exit(0)
        # EMM uses ber encoding for LCSCLientId object
        if len(fuzz_result.to_ber()) <= 255:
            break

    return result, len(fuzz_result.to_ber())


def generate_LCSClientID_msg():
    """
    Generate a random LCSClientID message

    Returns:
        result (bytes): The generated LCSClientID message.
    """

    while (True):
        bb = MAP.MAP_LCS_DataTypes.LCS_ClientID
        fuzz_result = MAP.MAP_LCS_DataTypes.LCS_ClientID

        result, mutation_paths, optional_paths = loop_IE(bb)
        logging.debug(result)
        logging.debug('-------------- Mutation paths --------------')
        logging.debug(mutation_paths)
        logging.debug('-------------- Optional paths --------------')
        logging.debug(optional_paths)
        logging.debug('-------------- Mutation --------------')
        logging.debug(result)
        try:
            fuzz_result.set_val(result)
        except Exception as e:
            logging.debug("error: ", e)
            exit(0)

        # EMM container only supports a LCSClientID of less than 255 bytes
        if len(fuzz_result.to_ber()) < 255:
            break

    return result, len(fuzz_result.to_ber()), mutation_paths, optional_paths


if __name__ == '__main__':
    # generate_LCSClientID_packet_test()
    generate_LCSClientID_msg()
