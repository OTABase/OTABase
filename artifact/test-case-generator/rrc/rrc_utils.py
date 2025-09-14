from rrc.releaseLTE_R17 import RRCLTE_R17
from pycrate_asn1rt import *
from pycrate_asn1rt.asnobj import ASN1Obj
import secrets
import random
import logging

import os
import math
import time

# Remove all asnlog
ASN1Obj._SILENT = True
ASN1Obj._SAFE_BND = False

def field_to_bits(elem: asnobj_str) -> str:
    """ Converts an ASN1 object to a string of bits (0 or 1)

    Args:
        elem (asnobj_str): ASN1 object

    Returns:
        str: string of bits
    """
    bytes_encoding = elem.to_uper()
    n = int.from_bytes(bytes_encoding, byteorder='big')
    width = ((len(bytes_encoding) * 8) + 7) // 8 * 8
    return format(n, f'0{width}b')


def bit_str_to_bytes(bit_str: str) -> bytes:
    """ Converts a string of bits (0 or 1) to bytes

    Args:
        bit_str (str): string of bits

    Returns:
        bytes: bytes
    """
    padding = (8 - len(bit_str) % 8) % 8
    bit_str += '0' * padding
    return bytes(int(bit_str[i:i+8], 2)
                 for i in range(0, len(bit_str), 8))


def bytes_to_bit_str(bytes: bytes) -> str:
    """ Converts bytes to a string of bits (0 or 1)

    Args:
        bytes (bytes): bytes to convert

    Returns:
        str: string of bits
    """
    return ''.join(format(byte, '08b') for byte in bytes)


def encode_unbound_length(length: int) -> list[bytes]:
    """ Encodes unbound length encoding

    3 different cases :
    1. If length (0, 127), encoded in* 1 byte
    2. If length (128, 16383) encoded in 2 bytes, bit 8 of octet 0 is always 1, bit 7 is always set to 0.
    3. If length is (16384 or more) encoded in 2 bytes, bit 8 of octet is always 1 and bit 7 of octet 1 is always 1
        multiple cases to cover here.

    Args:
        length (int): length to encode

    Returns:
        list[bytes]: encoded length
    """
    # Accordig to PER specs max length should be 64k (subclause 10.9.1)
    assert length < 2**16
    match length:
        case _ if length <= 127:
            return [length.to_bytes(1, byteorder='big')]
        case _ if length < 2**14 and length > 127:
            # Set bit8 of octet0 to 1
            return [(length | 2**15).to_bytes(2, byteorder='big')]
        case _ if length >= 2**14:
            counter = length // 2**14
            remainder = length % 2**14
            return [(0b11 << 14 | counter).to_bytes(2, byteorder='big')] + encode_unbound_length(remainder)


def decode_unbound_length(bytes_encoding: bytes) -> int:
    """ Decodes unbound length encoding

    Args:
        bytes_encoding (bytes): bytes to decode

    Returns:
        int: decoded length
    """
    byte_0 = bytes_encoding[0:1]
    encoding = int.from_bytes(byte_0, byteorder='big')
    if encoding & 2**7:
        # Length encoded on two bytes
        encoding = int.from_bytes(bytes_encoding[:2], byteorder='big')
        if encoding & 2**15 and encoding & 2**14:
            counter = encoding & 7
            return 2**14 * counter
        elif encoding & 2**15:
            return encoding ^ 2**15
    else:
        return encoding


def generate_random_bytes(n: int) -> bytes:
    """ Generates n random bytes

    Args:
        n (int): number of bytes to generate

    Returns:
        bytes: random bytes
    """

    return bytes(random.getrandbits(8) for _ in range(n))


def n_random_bits(n: int) -> str:
    """ Generates a random bit string of length n

    Args:
        n (int): length of the bit string to generate

    Returns:
        str: random bit string of length n
    """
    if n == 0:
        return ''
    return format(secrets.randbits(n), f'0{n}b')


def generate_invalid_length_encoding() -> int:
    """ Generates an invalid length encoding for unbound length

    Returns:
        int: invalid length encoding
    """
    # Between 0b1100000000000101 and 0b1111111111111111
    return random.randrange(49157, 2**16 - 1).to_bytes(2, byteorder='big')


def bitl_to_bytel(bit_length: int) -> int:
    """Converts a bit length to a byte length
    """
    byte_length = bit_length // 8
    if bit_length % 8 != 0:
        byte_length += 1
    return byte_length


def remove_embedded_field_indicator(field_path: list[str]) -> list[str]:
    """ Removes the embedded field indicator '*' from the field path
    Note that only an octet string can contain embedded fields

    Args:
        field_path (list[str]): field path

    Returns:
        list[str]: field path without the embedded field indicator
    """

    field_path = list(field_path)
    while '*' in field_path:
        logging.debug('Embedded')
        field_path.remove('*')

    return field_path


def remove_sequence_of_item_name(field_path: list[str]) -> list[str]:
    """ Removes the sequence of item name and indicator incase there is a seqof in a seqof
    Indicated by a '^' and followed by the name.

    Args:
        field_path (list[str]): field path

    Returns:
        list[str]: field path without the indicator and item name
    """

    field_path = list(field_path)
    while '^' in field_path:

        index = field_path.index('^')
        # Remove the target element
        field_path.pop(index)
        # Check if there is an element after the target and remove it
        if index < len(field_path):
            field_path.pop(index)
    return field_path


def remove_sequence_of_item_indicator(field_path: list[str]) -> list[str]:
    """ Removes the sequence of item name and indicator incase there is a seqof in a seqof
    Indicated by a '^' and followed by the name.

    Args:
        field_path (list[str]): field path

    Returns:
        list[str]: field path without the indicator and item name
    """

    field_path = list(field_path)
    while '__elem__' in field_path:
        index = field_path.index('__elem__')
        # Remove the target element
        field_path.pop(index)

    return field_path


def get_field(packet: asnobj_str, field_path: list[str]) -> asnobj_str:
    """ Returns the field in the packet corresponding to the field path

    Args:
        packet (asnobj_str): packet to extract the field from
        field_path (list[str]): field path

    Returns:
        asnobj_str: field in the packet corresponding to the field path
    """
    field_path = remove_embedded_field_indicator(field_path)
    field_path = remove_sequence_of_item_name(field_path)
    field_path = remove_sequence_of_item_indicator(field_path)

    if packet.get_at(field_path).get_val() != packet.get_val_at(field_path):
        packet.get_at(field_path).set_val(packet.get_val_at(field_path))

    assert packet.get_at(field_path).get_val() == packet.get_val_at(field_path)

    return packet.get_at(field_path)


def get_field_bits(field: asnobj_str) -> str:
    """ Removes the padding bits of a field when converted to bit strings
    This is necessary to corerectly identify the field in the packet

    Args:
        field (asnobj_str): field to remove padding bits from

    Returns:
        str: field converted to bit string without padding bits

    """
    field_bits = bytes_to_bit_str(field.to_uper())
    match field.TYPE:

        case 'OCTET STRING':
            if field._const_sz != None:

                field_max_length = field._const_sz.ub - field._const_sz.lb

                # Minimum number of bits required to represent field_max_length
                len_bit_size = math.floor(
                    math.log2(field_max_length)) + 1

                # Remove padding bits to find the field in the packet later
                if len_bit_size % 8 != 0:
                    excess_length = 8 - len_bit_size % 8
                    field_bits = field_bits[:-excess_length]

            return field_bits

        case 'BIT STRING':
            if field._const_sz != None:
                # Bounded length case, length is encoded on the min number of bits required to represent field_max_length
                logging.debug('Constrainted length bit mutation')

                field_max_length = field._const_sz.ub - field._const_sz.lb

                # Minimum number of bits required to represent field_max_length
                length_value_bit_size = math.floor(
                    math.log2(field_max_length)) + 1

                content_length = int(
                    field_bits[:length_value_bit_size], 2) + field._const_sz.lb

                # Removing padding bits
                field_bits = field_bits[:(
                    content_length + length_value_bit_size)]

            return field_bits

        case 'SEQUENCE':
            field_bits = bytes_to_bit_str(field.to_uper())
            return field_bits

        case 'INTEGER':
            range = field._const_val.root[0]

            field_max_length = range.ub - range.lb

            # Minimum number of bits required to represent field_max_length
            field_bit_length = math.floor(
                math.log2(field_max_length)) + 1
            field_bits = bytes_to_bit_str(field.to_uper())[:field_bit_length]

            return field_bits

        case 'SEQUENCE OF':
            # !!! This does not return the exact bits for SEQOF !!!
            # It only returns the length componenent of the SEQOF for simplicity and avoid padding struggles
            # Minimum number of bits required to represent field_max_length
            field_max_length = field._const_sz.ub - field._const_sz.lb
            len_bit_size = math.floor(
                math.log2(field_max_length)) + 1

            return field_bits[:len_bit_size]
        case _:
            logging.error(f'Field type {field.TYPE} not supported')
            os._exit(0)


def find_field_bit_index(packet_uper_bits: str, target_field_uper_bits: str, target_field_path: list) -> int:
    """ Finds the starting index of a field in a packet given the field bits

    Args:
        packet_uper_bits (str): bit string representing the packet
        target_field_uper_bits (str): bit string representing the field
        target_field_path (list): path of the field in the packet

    Returns:
        int: starting index of the field in the packet
    """

    indices = find_all(packet_uper_bits, target_field_uper_bits)

    if len(indices) == 0:
        logging.error(
            f'Field {target_field_uper_bits} not found in packet {packet_uper_bits}')
        os._exit(0)

    if len(indices) > 1:
        # In this case, we modify the field again to eliminate the ambiguity of the start index
        packet = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message
        packet.from_uper(bit_str_to_bytes(packet_uper_bits))

        target = get_field(packet, target_field_path)
        # This has to be done for fields in SEQ OF as they are all build with the same patron
        target.set_val(packet.get_val_at(target_field_path))

        match target.TYPE:

            case 'SEQUENCE OF':
                # Minimum number of bits required to represent field_max_length
                field_max_length = target._const_sz.ub - target._const_sz.lb
                len_bit_size = math.floor(
                    math.log2(field_max_length)) + 1

                old_value = packet.get_val_at(target_field_path)

                lb, ub = target._const_sz.lb, target._const_sz.ub
                assert lb != ub

                current_length = len(target.get_val())

                if current_length == ub:
                    new_length_value = current_length + 1
                else:
                    new_length_value = current_length - 1

                new_value = []
                new_value = old_value
                while len(new_value) < new_length_value:
                    new_value += old_value
                new_value = new_value[:new_length_value]

                packet.set_val_at(target_field_path, new_value)

                target.set_val(new_value)

                new_target = get_field(packet, target_field_path)

                new_packet_bits = get_field_bits(packet)
                new_target_bits = get_field_bits(new_target)
                new_indices = find_all(
                    new_packet_bits, new_target_bits[:len_bit_size])
                indices = new_indices.intersection(indices)

                # We take the smallest index after intersection
                # This is because when we are altering the length we can create new matches in the new packet that previously didnt existed in the old one
                return min(list(indices))

            case 'OCTET STRING':
                if target._const_sz != None:
                    old_value = packet.get_val_at(target_field_path)
                    old_length = len(old_value)
                    length = old_length
                    value = old_value
                    while (value == old_value):
                        value = random.randbytes(length)
                    packet.set_val_at(target_field_path, value)
                    # This is done in case of field being a SEQ OF element, need to reset the value of the pattern used to build the seqof elements
                    target.set_val(value)
                    new_target = get_field(packet, target_field_path)
                    new_target_bits = get_field_bits(new_target)
                    new_packet_bits = get_field_bits(packet)
                    new_indices = find_all(new_packet_bits, new_target_bits)
                    indices = new_indices.intersection(indices)
                    assert len(indices) == 1

                else:
                    logging.error(
                        'Unconstrained Octet String finding not implemented')
                    os._exit(0)

            case 'BIT STRING':
                if target._const_sz != None:

                    if target.get_val() != packet.get_val_at(target_field_path):
                        logging.warning(
                            'Target field did not match packet field')
                        os._exit(0)
                    old_value, old_length = packet.get_val_at(
                        target_field_path)

                    length = old_length
                    value = old_value
                    while (value == old_value):
                        value = random.randint(0, 2**length - 1)

                    packet.set_val_at(target_field_path,
                                      (old_value, old_length))

                    assert target == packet.get_at(target_field_path)

                    packet.set_val_at(target_field_path, (value, length))

                    # This is done in case of field being a SEQ OF element
                    target.set_val((value, length))
                    new_target = get_field(packet, target_field_path)
                    new_target.set_val((value, length))

                    if new_target.get_val() != (value, length):
                        logging.error('Target field not modified correctly')
                        os._exit(0)

                    new_target_bits = get_field_bits(new_target)
                    new_packet_bits = get_field_bits(packet)

                    new_indices = find_all(new_packet_bits, new_target_bits)
                    indices = new_indices.intersection(indices)

                    # Reset the value
                    packet.set_val_at(target_field_path,
                                      (old_value, old_length))
                    # This is done in case of field being a SEQ OF element
                    packet.get_at(target_field_path).set_val(
                        (old_value, old_length))

                    assert len(indices) == 1
                else:
                    logging.error(
                        "Unconstrained octet string correction not implemented")
                    os._exit(0)

            case _:
                logging.error(
                    f'Field type {target.TYPE} not supported for index ambuguity correction')
                print(len(indices))
                os._exit(0)

    assert len(indices) == 1
    return indices.pop()


def find_all(packet_bits, target_bits):
    indices = set()
    start_index = 0
    while True:
        index = packet_bits.find(
            target_bits, start_index)

        if index == -1:
            break
        indices.add(index)
        start_index = index + 1
    return indices


def replace_field_with_mutations(packet_bits: str, field_bits: str, index: int, mutation: str) -> str:
    """ Replace a field in a packet with a list of mutations

    Args:
        packet_bits (str): bit string representing the packet
        field_bits (str): bit string representing the field to replace
        index (int): index of the field in the packet
        mutations (list): list of bit strings representing the mutations

    Returns:
        str: bit string of the mutated packets

    """

    head = packet_bits[:index]
    tail = packet_bits[index + len(field_bits):]
    field = packet_bits[index: index + len(field_bits)]
    mutated_packet_bits = head + mutation + tail
    assert field == field_bits

    return mutated_packet_bits


def set_ancestor_length_in_packet(packet_uper_bits: str, ancestor_field: asnobj_str, ancestor_field_path: list, delta: int):
    """ Set the length of an ancestor field in a packet
    Ancestor field contain the field to mutate. The length of the ancestor field is updated if the field is modified. 
    This is done to keep correctness of the packet for the ancestor field and target the mutation to the inside field.
    

    Args:
        packet_uper_bits (str): bit string representing the packet
        ancestor_field (asnobj_str): ancestor field to replace the length of
        ancestor_field_path (list): path of the ancestor field in the packet
        delta (int): delta to apply to the length of the ancestor field
    
    Returns:
        str: bit string of the mutated packet
    """

    if (delta % 8 != 0):
        logging.error('Delta is not byte aligned')
        os._exit(0)

    byte_delta = delta // 8

    ancestor_field_uper = ancestor_field.to_uper()
    ancestor_field_uper_bits = get_field_bits(
        ancestor_field)
    index = find_field_bit_index(
        packet_uper_bits, ancestor_field_uper_bits, ancestor_field_path)

    logging.debug(f'Ancestor field {ancestor_field}')
    logging.debug(f'Ancestor index {index}')
    logging.debug(f'Ancestor field bits {ancestor_field_uper_bits}')

    if ancestor_field._const_sz != None:
        logging.error('Ancestor to replace length with is bound')
        os._exit(0)

    decoded_length = decode_unbound_length(ancestor_field_uper)

    logging.debug(f'Decoded ancestor length {decoded_length}')

    old_length_bytes = ancestor_field_uper[0:1]
    if decoded_length > 127:
        old_length_bytes = ancestor_field_uper[0:2]

    old_length_bits = bytes_to_bit_str(old_length_bytes)
    logging.debug(f'Old length bits {old_length_bits}')
    new_length = decoded_length + byte_delta
    assert new_length > 0

    logging.debug(f'New length {new_length}')

    new_length_bytes = encode_unbound_length(new_length)
    new_length_bits = bytes_to_bit_str(new_length_bytes[0])

    logging.debug(f'New length bits {new_length_bits}')
    if len(new_length_bytes) > 1:
        logging.error(
            'New length means that data is encoded on two blocks (should not happend for OTA)')
        os._exit(0)

    return replace_field_with_mutations(packet_uper_bits, old_length_bits, index, new_length_bits)


def split_list_of_lists(original_list, split_list):
    before_list = []
    after_list = []
    split_found = False

    if split_list not in original_list:
        logging.error('Split list not in original list')
        os._exit(0)

    for path in original_list:
        if not split_found and all(item in path for item in split_list):
            before_list.append(path)
            split_found = True
        elif split_found:
            after_list.append(path)
        else:
            before_list.append(path)

    return before_list, after_list


def find_paths_to_delete_multi(keep: list[list[str]], optional_paths: list[list]) -> set:
    """ 
    Filters all paths to delete by sorting the paths that are not ancestors or not childrens of
    the path to keep.

    Args:
        all_paths (list[path]): list of all paths
        keep (path): path to keep

    Returns:
        list[path]: all paths to delete that are not ancestors and not childrends of the path to keep
    """
    # Identify paths that are ancestors of the path to keep
    # ancestors = []
    # # Child paths are only happen with SEQ OF or embedded OCT STR as target
    # childrens = []
    start_time = time.time()
    to_delete = []
    ancestors = []
    childrens = []
    for path in optional_paths:

        found = False
        for k in keep:
            if path == k:
                found = True
                break
            if path != k and len(k) > len(path) and k[:len(path)] == path:
                ancestors.append(path)
                found = True
                break
            elif path != k and len(k) < len(path) and path[:len(k)] == k:
                childrens.append(path)
                found = True
                break
        if not found:
            to_delete.append(path)

    return to_delete, ancestors, childrens


def find_paths_to_delete_simple(keep: list[str], optional_paths: list[list]) -> set:
    """ 
    Filters all paths to delete by removing the paths that are not ancestors or not childrens of
    the path to keep.

    Args:
        all_paths (list[path]): list of all paths
        keep (path): path to keep

    Returns:
        list[path]: all paths to delete that are not ancestors and not childrends of the path to keep
    """
    # Identify paths that are ancestors of the path to keep
    ancestors = []
    # Child paths are only happen with SEQ OF or embedded OCT STR as target
    childrens = []
    to_delete = []
    for path in optional_paths:
        if path == keep:
            continue
        if path != keep and len(keep) > len(path) and keep[:len(path)] == path:
            ancestors.append(path)
        elif path != keep and len(keep) < len(path) and path[:len(keep)] == keep:
            childrens.append(path)
        else:
            to_delete.append(path)

    return to_delete, ancestors, childrens


def get_target_ancestors_path(target_field_path: list, mutation_paths: list) -> list:
    """ Get the ancestors of the target field that are in the mutation paths

    Args:
        target_field_path (list): the path of the target field in the packet
        mutation_paths (list): the list of all paths that lead to a field that can be mutated

    Returns:
        list: the list of ancestors of the target field that are in the mutation paths sorted by length
    """
    ancestors = set()
    for path in mutation_paths:
        if (path != target_field_path
                and len(target_field_path) > len(path)
                and target_field_path[:len(path)] == path):
            ancestors.add(tuple(path))
    return sorted(ancestors, key=len)


# Reduces a list of paths to delete by finding the shortest full path prefix match
# Removes path deletion order issues and avoids sorting all the paths


def reduce_paths(paths, children_paths):
    """
    Reduces the number of paths to delete by leveraging the deletion of ancestor paths
    Assumes that the paths to reduce are sorted such that the ancestor paths are handled first
    Because we collect the paths during a DFS traversal this is not an issue
    Args:
        paths (list[path]): a list of path

    Returns:
        list[path]: the minimum amount of paths that need to be deleted
    """

    unique_paths = list()
    for path in paths:
        if len(unique_paths) == 0 and path not in children_paths:
            unique_paths.append(path)

        else:
            last_path = unique_paths[-1]
            if path[:len(last_path)] != last_path and path not in children_paths:
                unique_paths.append(path)

    return unique_paths


def delete_fields(msg, delete_paths):
    """
    Deletes all fields that are reached with a path to delete
    This simplifies the message and reduces considerably the size of the message

    Args:
        msg (dict): a RRC message
        delete_paths (list[path]): paths to the fields to delete

    Returns:
        dict: simplified msg with unnecessary fields removed
    """
    simplified_message = msg
    for p in delete_paths:
        skip_del = False
        skip_next_key = False
        curr_msg = simplified_message
        # logging.debug(f'Removing {p}')
        # Traverse the dictionary using the keys in the path
        parent_msg = simplified_message
        last_key = ''

        for i, key in enumerate(p[:-1]):
            if skip_next_key:
                skip_next_key = False
                continue
            # Unpack bytes
            if key == '*' and type(curr_msg) is bytes:
                embedded = RRCLTE_R17.GLOBAL.MOD['EUTRA-RRC-Definitions'][p[i + 1]]
                embedded.from_uper(curr_msg)
                # Deletion happens here
                r = delete_fields(embedded.get_val(), [p[i+2:]])
                embedded.set_val(r)
                parent_msg[last_key] = embedded.to_uper()
                # Skip deletion as it already happened
                skip_del = True
                break
            if key == '*' or '__elem__' == key:
                continue
            if key == '^':
                skip_next_key = True
                continue
            if type(curr_msg) is tuple:
                assert key == curr_msg[0]
                parent_msg = curr_msg
                last_key = 1
                curr_msg = curr_msg[1]
            else:
                try:
                    parent_msg = curr_msg
                    last_key = key
                    curr_msg = curr_msg[key]
                except Exception:
                    # Next element in the path does not exist
                    logging.debug('-----------------------')
                    with open('debug/paths_to_del.txt', 'w') as f:
                        f.write(str(delete_paths))
                    with open('debug/full_msg.txt', 'w') as f:
                        f.write(str(simplified_message))
                    logging.debug(f'Removing {p}')
                    logging.debug(
                        f'Exception occured accessing {key} in {curr_msg}')
                    os._exit(0)
        # logging.debug('Deletion choice .....')
        # logging.debug(skip_del)
        if not skip_del:
            # logging.debug('Deletion happened')
            # logging.debug(curr_msg)
            del curr_msg[p[-1]]

    return simplified_message


# Get all field names in the packet

def extract_all_ies(rrc_packet):
    """
    Extract all IE names from the packet

    Args:
        rrc_packet (asnobj_str): RRC packet

    Returns:
        set: set of IE names
    """

    packet_fields = rrc_packet.get_internals()['val']
    # Iterate of packet_fields dict and extract all keys into a set
    # Recursively

    def extract_keys(packet_fields):
        keys = set()

        if isinstance(packet_fields, dict):
            for k, v in packet_fields.items():
                keys.add(k)
                keys = keys.union(extract_keys(v))
        elif isinstance(packet_fields, tuple):
            if isinstance(packet_fields[0], str):
                keys.add(packet_fields[0])
                keys = keys.union(extract_keys(packet_fields[1]))

        elif isinstance(packet_fields, list):
            for v in packet_fields:
                keys = keys.union(extract_keys(v))

        return keys

    res = extract_keys(packet_fields)
    return res


def find_keys_with_hierarchy(data, path=[]):
    keys = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = path + [key]
            keys.append((current_path, key))
            keys.extend(find_keys_with_hierarchy(value, current_path))
    elif isinstance(data, (tuple)):
        if len(data) > 1:
            keys.append((path + [data[0]], data[0]))
            keys.extend(find_keys_with_hierarchy(data[1], path + [data[0]]))
        else:
            keys.extend(find_keys_with_hierarchy(data[0], path))
    elif isinstance(data, (list)):
        for value in data:
            keys.extend(find_keys_with_hierarchy(value, path))

    return keys


def collect_IE_names(message, path):
    """"
    Collects all IE names that are found in the path

    Args:
        message (asnobj_str): RRC packet
        path (list): path to the field

    Returns:
        set: set of IE names in the path
    """
    first_elements = set()

    current_data = message
    # print("=====================================")
    # print(f"path:{path}")
    for i, path_element in enumerate(path):
        try:
            if type(current_data).__name__ == 'SEQ_OF':
                if hasattr(current_data, '_cont'):
                    _cont = current_data._cont
                    if hasattr(_cont, '_tr'):
                        if hasattr(_cont._tr, '_name'):
                            first_elements.add(_cont._tr._name)
                # print(f"Target path_element : {path_element}")
                current_data = current_data._cont._cont[path_element]
                if hasattr(current_data, '_tr'):
                    if hasattr(current_data._tr, '_name'):
                        first_elements.add(current_data._tr._name)
                if hasattr(current_data, '_cont'):
                    _cont = current_data._cont
                    if hasattr(_cont, '_tr'):
                        if hasattr(_cont._tr, '_name'):
                            first_elements.add(_cont._tr._name)
            else:
                current_data = current_data._cont[path_element]
        except TypeError as e:
            logging.debug(f"Error: {e}. Skipping this as the object is None or does not support the operation.")

        if current_data is None:
            break

        # if isinstance(current_data, Cont) else None
        root_path = current_data.get_root_path()[0]
        first_elements.add(root_path)

        if hasattr(current_data, '_tr'):
            if hasattr(current_data._tr, '_name'):
                first_elements.add(current_data._tr._name)

        if i == len(path) - 1:
            if hasattr(current_data, '_cont'):
                _cont = current_data._cont
                if hasattr(_cont, 'get_root_path'):
                    first_elements.add(_cont.get_root_path()[0])

                if hasattr(_cont, '_tr'):
                    if hasattr(_cont._tr, '_name'):
                        first_elements.add(_cont._tr._name)

    return first_elements


def extract_all_ie_names(rrc_packet):
    """
    Extract all IE names from the packet

    Args:
        rrc_packet (asnobj_str): RRC packet

    Returns:
        set: set of IE names
    """
    packet_fields = rrc_packet.get_internals()['val']

    field_and_paths = find_keys_with_hierarchy(packet_fields)

    IEs = set()

    for path, key in field_and_paths:
        IEs.update(collect_IE_names(rrc_packet, path))

    return IEs
