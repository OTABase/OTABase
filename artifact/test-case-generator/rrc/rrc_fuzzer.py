from copy import deepcopy
import os
import threading
import json
import math
import logging
from rrc.releaseLTE_R17 import RRCLTE_R17

from pycrate_asn1rt import *
from rrc.rrc_generator import RRCGenerator
from rrc.rrc_stats import get_target_field_count, get_total_ie_count
from rrc.rrc_utils import *
from utils.logging_config import setup_logging
from abstract_classes.fuzzer import Fuzzer
from enum import Enum
import logging
from random import seed, randint
import pandas as pd

# Ensure logging is configured
setup_logging()


# # For reproducibility
# seed(19)
class RRCStrategy(Enum):
    BASE = 'BASE'
    TRUNCATE = 'TRUNCATE'
    ADD = 'ADD'


class RRCFuzzer(Fuzzer):

    MAX_OTA_RRC_PACKET_SIZE = 2048
    OVERFLOW_LEN = 100
    QUEUE_SIZE = 2000

    def __init__(self, targets, cycles=1, strategies=[RRCStrategy.BASE, RRCStrategy.ADD], seed=19, max_recur_depth=0, debug_mode=False) -> None:
        super().__init__(seed, cycles=cycles)
        # print(f"RRCFuzzer initialized with seed: {seed}")
        self.strategies = strategies
        self.debug_mode = debug_mode
        
        # Import logging (needed for all logging calls)
       
        
        # Enable debug logging if in debug mode
        if self.debug_mode:
            from utils.logging_config import setup_logging
            setup_logging(level=logging.DEBUG)
        # Add is not a strategy by itself but more like a generation option
        # if RRCStrategy.ADD not in self.strategies:
        #     strategies.append(RRCStrategy.ADD) 
        self.targets = targets
        self.max_recur_depth = max_recur_depth

        # NEEDS CHANGE IF TARGET FIELDS CHANGE
        self.rrc_generator = RRCGenerator(
            targets=targets, max_recur_depth=max_recur_depth, seed=seed)
        w_recur = not (self.max_recur_depth == 0)
        self.total_targets = get_target_field_count(
            targets=targets, w_recur=w_recur)
        
        self.searching = False
        self.priority_path = []
        self.N = 1
        self.discarded = 0
        self.total_coverage = get_total_ie_count()
        
        # Only load debug files in debug mode
        if self.debug_mode:
            # Check if file exists that contains the current grammar_coverage
            if os.path.isfile('rrc_coverage/full_grammar_coverage_set.json'):
                # This file stores all the IEs that have been covered by the fuzzer (delete to reset)
                with open('rrc_coverage/full_grammar_coverage_set.json', 'r') as file:
                    # Read the JSON data as a list
                    self.grammar_coverage = set(json.load(file))
                logging.debug("Loaded existing grammar coverage from rrc_coverage/full_grammar_coverage_set.json")
            else:
                self.grammar_coverage = set()
                
            if os.path.isfile('rrc_coverage/full_IE_name_coverage_set.json'):
                # This file stores all the IEs that have been covered by the fuzzer (delete to reset)
                with open('rrc_coverage/full_IE_name_coverage_set.json', 'r') as file:
                    # Read the JSON data as a list
                    self.ie_name_coverage = set(json.load(file))
                logging.debug("Loaded existing IE name coverage from rrc_coverage/full_IE_name_coverage_set.json")
            else:
                self.ie_name_coverage = set()
        else:
            self.grammar_coverage = set()
            self.ie_name_coverage = set()
        self.grammar_df = pd.DataFrame(columns=['packet_num', 'ie_coverage', 'total_coverage', 'ie_name_coverage','cycle'])
        self.payload_num = 0
        
        logging.info(f'Current cycle: {self.current_cycle}')

    def get_coverage(self):
        """Computes the current coverage of the fuzzer

        Returns:
            float: between 0 and 1, the current coverage of the fuzzer
        """
        assert len(self.coverage_map) <= self.total_targets
        return len(self.coverage_map) / self.total_targets
    
    
    def start_search(self):
        logging.debug('Starting worker thread')
        self.searching = True
        t = threading.Thread(target=self.fill_queue).start()
    
    def get_next_packet(self) -> tuple:
        """
        Get the next packet from the fuzzer

        Whenever the fuzzing cycle is finished, the fuzzer will reset its coverage map 
        and update its strategy.

        Returns:
            tuple: next packet
        """
        if not self.searching:
            logging.debug('Starting worker thread in get_next_packet')
            self.searching = True
            t = threading.Thread(target=self.fill_queue).start()

        # Finished cycle
        # TODO MOVE THIS TO FILL_QUEUE
        if self.get_coverage() == 1 and self.rollback_queue.empty():
            logging.info(f'Finished cycle {self.current_cycle}')
            self.current_cycle += 1
            if self.finished():
                logging.info('Finished fuzzing')
                
                
                
                # Write indicator to grammar_df
                new_df = pd.DataFrame({'packet_num': [-1], 
                    'ie_coverage': [self.seed], 
                    'total_coverage': [self.total_coverage],
                    'ie_name_coverage': [self.ie_name_coverage],
                    'cycle' : [-1]},
                    index=[len(self.grammar_df)])

                self.grammar_df = pd.concat([self.grammar_df, new_df])
                

                # Save coverage dataframe to csv file 
                
                # Only write debug files in debug mode
                if self.debug_mode:
                    # Ensure rrc_coverage directory exists
                    os.makedirs('rrc_coverage', exist_ok=True)
                    
                    # If file exist append to it
                    if os.path.isfile('rrc_coverage/grammar_coverage_add.csv'):
                        self.grammar_df.to_csv('rrc_coverage/grammar_coverage_add.csv', mode='a', header=False, index=False)
                    else:
                        self.grammar_df.to_csv('rrc_coverage/grammar_coverage_add.csv', index=False)
                    
                    # Write self.grammar_coverage to file
                    with open('rrc_coverage/full_grammar_coverage_set.json', 'w') as file:
                        json.dump(list(self.grammar_coverage), file)
                    
                    # Write self.ie_name_coverage to file
                    with open('rrc_coverage/full_IE_name_coverage_set.json', 'w') as file:
                        json.dump(list(self.ie_name_coverage), file)
                    
                    logging.debug("Debug files written to rrc_coverage/: grammar_coverage_add.csv, full_grammar_coverage_set.json, full_IE_name_coverage_set.json")
                    
                return None, None, None

            # Reset coverage map
            self.coverage_map = set()
            
            # TODO Remove this 
           
            logging.debug(f'New strategies : {self.strategies}')

            # Reset generator coverage map
            self.rrc_generator.reset_found()

            self.searching = False

            return self.get_next_packet()

        packet, path, strategy = self.rollback_queue.get()
      
        return packet, path, strategy

        

    def fill_queue(self):
        """Fills the rollback queue with packets to be mutated
        This function is called in a separate thread to avoid blocking the main thread,
        that serves the packets to the fuzzer clients
        """
        logging.debug('Worker thread started')
        
        if self.current_cycle > self.cycles:
            self.searching = False
            return 
        if self.get_coverage() == 1:
            self.searching = False
            return

        packet, mutation_paths, optional_paths = dict(), list(), list()

        while (self.rollback_queue.qsize() < 10 and self.get_coverage() < 1):
            data, packet, mutation_paths, optional_paths = self.rrc_generator.generate_packet()
            # print("Fuzzer got data from generator")
            # print(data.hex())
            if len(mutation_paths) == 0:
                continue
            for path in mutation_paths:
                # Remove SEQOF index for coverage computation
                unique_path = tuple(
                    [x for x in path if not isinstance(x, int)])

                if unique_path not in self.coverage_map:
                    # Update generator coverage map to optimize generation speed
                    self.rrc_generator.add_to_found(unique_path)
                    # Deepcopy is required as the packet is simplified during mutation
                    other = deepcopy(packet)
                    mutations = self.mutate_packet(
                        other, path, mutation_paths, optional_paths)

                    # # Deepcopy is required if this holds
                    # assert other != packet
                    
                    logging.debug(f'Adding new mutations to queue')
                    self.coverage_map.add(unique_path)

                    
                    # Only add non-blacklisted elements to the queue
                    while self.rollback_queue_lock.locked():
                        pass
                    
                    for strategy, m in mutations.items():
                        if not self.is_blacklisted((unique_path[-1], strategy)) and len(m) > 0 \
                            and len(m) < 1024 - (4 + 1) and unique_path[2] != "rrcConnectionRelease":
                            for n in m:
                                self.rollback_queue.put((n, unique_path, strategy))
                    else: 
                        if len(m) < 1024 - (4 + 1):
                            self.discarded += 1

        self.searching = False
        return
    
    def filter_queue(self):
        self.rollback_queue_lock.acquire()
        temp_items = []

        while not self.rollback_queue.empty():
            payload, path, strategy = self.rollback_queue.get()
            if not self.is_blacklisted((path[-1], strategy)):
                temp_items.append((payload, path, strategy))

        # Re-enqueue valid items
        for item in temp_items:
            self.rollback_queue.put(item)
        
        self.rollback_queue_lock.release()

    def prioritize_path_to_add(self, path):
        """
        Prioritize the path to add a field to the packet
        """
        self.priority_path = path

    
    def balanced_add_strategy(self, target_path, mutation_paths):
        """Returns the paths required to apply the add strategy
        
        The balanced add strategy consists of adding selecting N fields to add to the packet.
        The selection happens by selecting N divergent paths (equally likely) from all the paths that come before the target path.
        This is done recursively until N paths are selected.
        
        Args:
            target_path (list): the path to the target field
            mutation_paths (list): the paths to the fields that can be mutated
        
        Returns:
            list: the paths to the fields that can be added
        """
        
        def find_earliest_difference(paths) -> int:
            """
            Find the earliest index where paths differ.
            If all paths are identical, returns -1.
            """
            min_length = min(len(path) for path in paths)
            for i in range(min_length):
                if len(set(path[i] for path in paths)) > 1:
                    return i
            return -1
        
        def split_into_buckets(paths) -> dict:
            """
            Split paths into buckets based on the earliest difference.
            """
            diff_index = find_earliest_difference(paths)
            if diff_index == -1:
                return {}

            buckets = {}
            for path in paths:
                key = path[diff_index] if diff_index < len(path) else None
                if key not in buckets:
                    buckets[key] = []
                buckets[key].append(path)
            return buckets

        def select_paths(paths):
            """
            Recursively select paths based on the earliest difference and random bucket selection.
            """
            if len(paths) == 1:
                return paths

            buckets = split_into_buckets(paths)
            if not buckets:
                return [random.choice(paths)]
            
            selected_buckets = random.sample(list(buckets.values()), k=self.N)
            selected_paths = [select_paths(bucket)[0] for bucket in selected_buckets if bucket]

            return selected_paths
        
        add_candidates = []

        before, _ = split_list_of_lists(mutation_paths, target_path)

        before.pop() # Remove the target path
        if len(before) == 0:
            return []
        add_candidates = before
    
        additionnal_fields_paths = select_paths(add_candidates)
     
        return additionnal_fields_paths
        

    def add_strategy(self, target_path, mutation_paths):
        """Returns the paths required to apply the add strategy

        The add strategy consists in adding a new field to the packet.
        Only add fields that come before the target field in the encoding.
        This is done by splitting the list of mutation paths at the target path.
        Because the list was collected during a DFS traversal of the grammar from start to end,
        the paths that come before the target path are the ones that can be added.

        Args:
            target_path (list): the path to the target field
            mutation_paths (list): the paths to the fields that can be mutated
        
        Returns:
            list: the paths to the fields that can be added
        """
        add_candidates = []

        before, _ = split_list_of_lists(mutation_paths, target_path)

        before.pop() # Remove the target path
        add_candidates = before
        
        additionnal_fields_paths = []
        if len(add_candidates) > 0 and len(add_candidates) >= self.N:
            
            if self.priority_path in mutation_paths:
                additionnal_fields_paths.append(self.priority_path)
            else:
                # Do not add the target field again
                while len(additionnal_fields_paths) < self.N:
                    # TODO Check if adding mutation paths or optional paths is better
                    new_element = random.choice(add_candidates)
                    if new_element != target_path and new_element not in additionnal_fields_paths:
                        additionnal_fields_paths.append(new_element)        
        else:
            logging.warning('Generation : Not enough paths to add - Skipping')
        
        return additionnal_fields_paths
    
    def truncate_strategy(self, mutations : list[bytes]):
        truncated_mutations = []
        for m in mutations:
            truncated_mutations.append(m[:random.randint(1, len(m)-1)])
        return truncated_mutations

    def mutate_packet(self, packet_fields: dict, target_path: list[str], mutation_paths: list[str], optional_paths: list[str]):
        """ Mutates a target field inside a packet reachable using target_field_path
        Addtionnaly, reduces the packet size by removing all non-targeted optional fields
        Supports a variety of mutation strategies :

        - Base strategy: only mutates the target field
        - Add strategy: Adds N additionnal fields to the packet alongside the target field

        Additonnaly, we also correct the ancestor field lengths that contain the target field
        This is required as the target field might have been mutated in size.
        It maintains the validity of the packet up to the mutated target field.

        Args:
            packet (dict): dictionnary of key-value pairs representing the RRC packet
            target_field_path (list): list of keys to reach the target field
            mutation_paths (list): list of mutation paths in the packet
            optional_paths (list): list of optional paths in the packet

        Returns:
            list[bytes]: different mutation for the packet, where target field is mutated
        """
   
        # logging.debug(f'Targeting field {target_path}')
        # logging.debug(f'Optional paths {optional_paths}')
        # logging.debug(f'Mutation paths {mutation_paths}')
        # logging.debug(f'Target field path {target_path}')

        
        # with open('debug/mutations.txt', 'w') as f:
        #     f.write(str(mutation_paths))
        # with open('debug/optional.txt', 'w') as f:
        #     f.write(str(optional_paths))
        # with open('debug/full_msg.txt', 'w') as f:
        #     f.write(str(packet_fields))
        
        
        # Remove embeebed field indicators and sequence_of item names
        true_target_path = remove_embedded_field_indicator(target_path)
        true_target_path = remove_sequence_of_item_name(true_target_path)   
        true_target_path = remove_sequence_of_item_indicator(true_target_path)       

        
        """
        Step 1: Remove all optional fields that are not in the target field path
        Apply ADD strategy if enabled
        """
        additionnal_fields_paths = []
        if RRCStrategy.ADD in self.strategies:
            additionnal_fields_paths = self.add_strategy(target_path, mutation_paths)
            additionnal_fields_paths = self.balanced_add_strategy(target_path, mutation_paths)
        paths_to_delete, _, childrens = find_paths_to_delete_multi(
            [target_path] + additionnal_fields_paths, optional_paths)
            
    
        logging.debug('Reducing paths')
        reduced_paths = reduce_paths(paths_to_delete, childrens)

        logging.debug('Deleting fields')
        simplified_packet_fields = delete_fields(packet_fields, reduced_paths)

        logging.debug('Done deleting fields')
        """
        Step 2: Identify ancestor fields path to the target field that can be mutated
        """
        logging.debug('Getting ancestor')
        target_field_ancestors_paths = get_target_ancestors_path(
            target_path, mutation_paths)

        """
        Step 3: Get target field and its encoding
        """
        
        logging.debug('Getting target field')
        # Payload
        simplified_packet = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message
        simplified_packet.set_val(simplified_packet_fields)

        packet_uper_bits = get_field_bits(simplified_packet)

        # Get embedded fields back
        packet = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message
        packet.from_uper(simplified_packet.to_uper())
        simplified_packet = packet

        target_field = simplified_packet.get_at(true_target_path)
        target_field_value = simplified_packet.get_val_at(true_target_path)
        
        # This has to be done for fields inside a SEQ OF
        target_field.set_val(target_field_value)

        target_field_uper_bits = get_field_bits(
            target_field)

        """
        Step 3.5: Collect grammar coverage (debug mode only)
        """

        if self.debug_mode:
            # Add all new IEs from the simplified packet to the grammar coverage
            self.grammar_coverage = self.grammar_coverage.union(extract_all_ies(simplified_packet))
            self.ie_name_coverage = self.ie_name_coverage.union(extract_all_ie_names(simplified_packet))
            
            # Field names not IE
            new_df = pd.DataFrame({'packet_num': [self.payload_num], 
                        'ie_coverage': [len(self.grammar_coverage)], 
                        'total_coverage': [self.total_coverage],
                        'ie_name_coverage': [len(self.ie_name_coverage)],
                        'cycle' : [self.get_cycle()]},
                        index=[len(self.grammar_df)])

            self.grammar_df = pd.concat([self.grammar_df, new_df])
            self.payload_num += 1

            # Write grammar coverage to file
            os.makedirs('rrc_coverage', exist_ok=True)
            with open('rrc_coverage/rrc_full_grammar_coverage_set.json', 'w') as file:
                json.dump(list(self.grammar_coverage), file)

        """
        Step 4: Mutate target field using basic strategy
        """
        # Basic mutation strategy
        basic_field_mutations = self.basic_strategy(
            simplified_packet, target_field, true_target_path)
        
        # If target field is an integer, no need to adapt the ancestor fields
        if target_field.TYPE != 'INTEGER':
            """
            Step 5-6 : Only for BIT STRING and OCTET STRING as the mutations 
            needs to be applied at the bit level 
            
            Step 5: Adapt the length of the ancestor fields for BIT STRING and OCTET STRING mutations
            This is necessary such that the mutated target field will be reached by the decoder
            """
            basic_packet_mutations = []

            # if len(target_field_ancestors_paths) != 0:
            #     logging.debug(f'Ancestor paths : {target_field_ancestors_paths}')
            # else:
            #     logging.debug('No ancestor paths')
            #     pass

            mutated_outer_packet_bits = []
            
            # For each mutation, adapt the length of the ancestor fields
            for m, delta in basic_field_mutations:
                if len(target_field_ancestors_paths) != 0 and delta != 0:
                    b = get_field_bits(simplified_packet)
                    for ancestor_path in target_field_ancestors_paths:
                        ancestor_field = get_field(
                            simplified_packet, ancestor_path)

                        if ancestor_field.TYPE != 'OCTET STRING':
                            logging.warning(
                                f'Ancestor is not a OCTET STRING but a {ancestor_field.TYPE}')
                            continue

                        b = set_ancestor_length_in_packet(
                            b, ancestor_field, ancestor_path, delta)

                    mutated_outer_packet_bits.append(b)
                    
            if len(mutated_outer_packet_bits) == 0:
                mutated_outer_packet_bits = [
                    packet_uper_bits] * len(basic_field_mutations)
            """
            Step 6: Re-build packets using the mutated target field bits
            """  
           
            basic_packet_mutations = []
            for packet_bits, mutation in zip(mutated_outer_packet_bits, list(map(lambda x: x[0], basic_field_mutations))):

                # Find index of target field
                target_field_index = find_field_bit_index(
                    packet_bits, target_field_uper_bits, true_target_path)

                mutated_packet = replace_field_with_mutations(
                    packet_bits, target_field_uper_bits, target_field_index, mutation)
                basic_packet_mutations.append(mutated_packet)

            basic_field_mutations = [bit_str_to_bytes(m) for m in basic_packet_mutations]
            
            
        truncate_mutations = []

        if RRCStrategy.TRUNCATE in self.strategies:
            truncate_mutations = self.truncate_strategy([simplified_packet.to_uper()])


        return {'BASE' : basic_field_mutations, 'TRUNCATE' : truncate_mutations}


    def basic_strategy(self, simplified_packet, target_field: asnobj_str, target_path: list) -> list[str]:
        """ Basic mutation strategy, mutates the target field only

        Args:
            target_field (asnobj_str): target field to mutate

        Returns:
            list[str]: list of mutations as string bits
        """
        mutations = []
        match target_field.TYPE:

            case t if t == 'INTEGER':
                logging.debug('Integer case')
                mutations = self.mutate_rrc_integer_field(
                    simplified_packet, target_field, target_path)

            case t if t == 'SEQUENCE OF':
                logging.debug('SEQUENCE OF case not supported')
                mutations = self.mutate_rrc_seqof_field(simplified_packet, target_field, target_path)

            case t if t == 'OCTET STRING':
                logging.debug('OCTET String case')
                mutations = self.mutate_rrc_octet_field(
                    target_field)

            case t if t == 'BIT STRING':
                logging.debug('BIT String case')
                mutations = self.mutate_rrc_bit_field(target_field)
                    
            case _:
                logging.error(f'No matching type {t} found in mutation')
                exit(0)

        return mutations
    
    def mutate_rrc_seqof_field(self, simplified_packet, field: asnobj_str, target_path: list) -> list[tuple]:
        """
        Mutate an RRC SEQOF field

        Args:
            field (RRC Obj): field to mutate
        
        Returns:
            list[(str, int)]: list of bit strings representing different mutations of the field
            each bit string is associated with the number of bytes that should be added to the ancestors length
        """
        
        mutations = []        
        field_bits = get_field_bits(field)
        num_elements = len(field.get_val_at([]))
        
        # Minimum number of bits required to represent field_max_length
        field_max_length = field._const_sz.ub - field._const_sz.lb
        len_bit_size = math.floor(
            math.log2(field_max_length)) + 1
        
        field_max_encoded_length = 2**len_bit_size - 1
        
        content = field_bits[len_bit_size:]
        
        # 0 length
        mutations.append((format(0, f'0{len_bit_size}b') + content, 0))
        #  Random length between 0 and field_max_length
        mutations.append((format(num_elements, f'0{len_bit_size}b') + content, 0))
        # random length between 0 and field_max_length
        mutations.append((format(randint(0, field_max_encoded_length), f'0{len_bit_size}b') + content, 0))
        # field_max_length
        mutations.append((format(field_max_encoded_length, f'0{len_bit_size}b') + content, 0))
       
        # Mutations of SEQOF number of element field should not modify the total bit length of the field
        assert len(mutations[0][0]) == len(field_bits)

        return mutations
        
        

    def mutate_rrc_octet_field(self, field: asnobj_str) -> list[tuple]:
        """
        Mutate an RRC OCTET STRING field

        Args:
            field (RRC Obj): field to mutate

        Returns:
            list[(str, int)]: list of bit strings representing different mutations of the field
            each bit string is associated with the number of bytes that should be added to the ancestors length
        """

        mutations = []
        field_bytes = field.to_uper()
        field_value = field.get_val_at([])
        field_size = len(field_bytes)

        # Length is encoded differently if constraint or not
        if field._const_sz != None:
            # Bounded length case, length is encoded on the min number of bits required to represent field_max_length
            logging.debug('Bounded length octet mutation')

            # Minimum number of bits required to represent field_max_length
            field_max_length = field._const_sz.ub - field._const_sz.lb
            len_bit_size = math.floor(
                math.log2(field_max_length)) + 1
            field_max_encoded_length = 2**len_bit_size - 1

            def gen_constrained_byte_field(length: int, content_length: int, initial_field_value=field_value, intial_field_size=field_size) -> tuple:
                """
                Generate a bit string representing a mutated field, uses the inital bytes of the field if possible

                Args:
                    length (int): length of the field
                    content_length (int): length of the buffer content
                    field_bytes (bytes): field bytes
                    initial_field_value (int, optional): initial field size. Defaults to field_size.

                Returns:
                    tuple(str, int): bit string representing the mutated field, size difference between the mutated field and the initial field
                """

                content = b''
                if content_length > len(initial_field_value):
                    content = initial_field_value + \
                        generate_random_bytes(
                            content_length - len(initial_field_value))
                else:
                    content = field_bytes[:content_length]

                mutated_field = format(
                    length, f'0{len_bit_size}b') + bytes_to_bit_str(content)
                delta = len(bit_str_to_bytes(mutated_field)) - \
                    intial_field_size
                return (mutated_field, delta * 8)

            """
            Mutations
            """
            # Length set to a valid length value, buffer content empty
            length = randint(0, field_max_length - 1)
            mutations.append(gen_constrained_byte_field(length, 0))

            # Length set to 0, buffer content set to OVERFLOW_LEN
            mutations.append(gen_constrained_byte_field(
                0, self.OVERFLOW_LEN))

            # Length set to buffer content length - 1, within valid length range
            length = randint(0, field_max_length - 1)
            content_length = length + field._const_sz.lb + 1
            mutations.append(gen_constrained_byte_field(
                length, content_length))

            # Length set to max encoded length, buffer contains the maxium amount of bytes the field can contain
            mutations.append(gen_constrained_byte_field(
                field_max_encoded_length, field._const_sz.ub))

            return mutations

        else:
            logging.debug('Unconstrained length octet mutation')

            length_mutations = [0, 127, 128, 2**14 - 1, 2**14, 2 *
                                (2**14),  2*(2**14) + 1, 3*(2**14), 3*(2**14) + 1, 2**16 - 1]

            def gen_unconstrained_byte_field(encoded_length: bytes, content_length: int, initial_field_value=field_value, intial_field_size=field_size) -> tuple:
                """
                Generate a bit string representing a mutated field, uses the inital bytes of the field if possible

                Args:
                    length (int): length of the field
                    content_length (int): length of the buffer content
                    field_bytes (bytes): field bytes
                    initial_field_value (int, optional): initial field size. Defaults to field_size.

                Returns:
                    tuple(str, int): bit string representing the mutated field, size difference between the mutated field and the initial field
                """

                content = b''
                if content_length > len(initial_field_value):
                    content = field_bytes + \
                        generate_random_bytes(
                            content_length - len(initial_field_value))
                else:
                    content = field_bytes[:content_length]

                # Ignore the second part of the length encoding
                # To big for OTA packets
                mutated_field = encoded_length[0] + content
                delta = len(mutated_field) - intial_field_size
                return (''.join(bin(byte)[2:].zfill(8)
                                for byte in mutated_field), delta * 8)

            for l in length_mutations:

                """
                Mutations
                """
                # Empty content

                encoded_length = encode_unbound_length(l)

                mutations.append(
                    gen_unconstrained_byte_field(encoded_length, 0))

                # Content length set to smaller than length l
                mutations.append(gen_unconstrained_byte_field(
                    encoded_length, randint(1, min(self.MAX_OTA_RRC_PACKET_SIZE, max(1, l - 1)))))

              
                # TODO Figure out what to do with this mutation as OTA has max packet size
                # Content length bigger than l

                # if len(field_bytes) < l:
                #     content = field_bytes + b'A' * (l - len(field_bytes))
                #     content = content + b'A' * self.OVERFLOW_LEN
                # else:
                #     content = field_bytes[:l]
                #     content = content + field_bytes[l: l + min(
                #         len(field_bytes) - l, self.OVERFLOW_LEN)]
                #     content = content + b'A' * \
                #         max(0, l + self.OVERFLOW_LEN - len(content))

                # assert len(content) == l + self.OVERFLOW_LEN
                # TODO Compute size delta
                # mutations.append(length + content)

            # Invalid length encoding mutation
            invalid_length_bytes = [generate_invalid_length_encoding()]
            invalid_length = int.from_bytes(invalid_length_bytes[0], 'big')
            mutations.append(gen_unconstrained_byte_field(
                invalid_length_bytes, 0))
            mutations.append(gen_unconstrained_byte_field(invalid_length_bytes, randint(
                1, min(self.MAX_OTA_RRC_PACKET_SIZE, max(1, invalid_length - 1)))))

            return mutations

    def mutate_rrc_bit_field(self, field: asnobj_str) -> list[tuple]:
        """
        Mutate an RRC BIT STRING field

        Args:
            field (RRC Obj): field to mutate

        Returns:
            str: bit string representing the mutated field
        """
        mutations = []
        length = 0

        field_bytes = field.to_uper()
        field_bits = get_field_bits(field)

        if field._const_sz != None:

            logging.debug('Constrainted length bit mutation')
            # Minimum number of bits required to represent field_max_length
            field_max_length = field._const_sz.ub - field._const_sz.lb
            len_bit_size = math.floor(
                math.log2(field_max_length)) + 1

            assert len_bit_size + \
                int(field_bits[: len_bit_size], 2) + \
                field._const_sz.lb == len(field_bits)

            def gen_constrained_bit_field(length_value: int, content_length: int) -> tuple:
                content_bits = n_random_bits(content_length)
                mutated_field = format(
                    length_value, f'0{len_bit_size}b') + content_bits
                delta = len(mutated_field) - len(field_bits)
                return (mutated_field, delta)

            """
            Mutations
            """
            # Length set to a valid length value, buffer content empty
            length = randint(0, field_max_length - 1)
            mutations.append(gen_constrained_bit_field(
                length, 0))

            # Length set to 0, buffer content set to OVERFLOW_LEN
            mutations.append(gen_constrained_bit_field(
                0, self.OVERFLOW_LEN + field._const_sz.lb))

            # Length set to buffer content length - 1, within valid length range
            length = randint(0, field_max_length - 1)
            content_length = length + field._const_sz.lb + 1
            mutations.append(gen_constrained_bit_field(
                length, content_length))

            # Length set to max possible length, buffer contains more than max possible length, outside valid length range
            field_max_length_value = 2**len_bit_size - 1
            mutations.append(gen_constrained_bit_field(
                field_max_length_value, field_max_length_value + self.OVERFLOW_LEN))

            return mutations

        else:
            logging.debug('Unconstrainted length bit mutation')

            length = decode_unbound_length(field_bytes)

            # OTA packet size is capped
            # length_mutations = [0, 127, 128, 2**14 - 1, 2**14, 2 *
            #                     (2**14),  2*(2**14) + 1, 3*(2**14), 3*(2**14) + 1, 2**16 - 1]
            length_mutations = [0, 127, 128]
            def gen_unconstrained_bit_field(encoded_length: bytes, content_length: int) -> tuple:
                content_bits = n_random_bits(content_length)
                length_bytes = encoded_length[0]
                length_bits = bytes_to_bit_str(length_bytes)
                mutated_field = length_bits + content_bits
                delta = len(mutated_field) - len(field_bits)
                return (mutated_field, delta)

            mutations = []

            for l in length_mutations:

                encoded_length = encode_unbound_length(l)
                # Length set to a valid length value, buffer content empty
                mutations.append(
                    gen_unconstrained_bit_field(encoded_length, 0))

                # Content length smaller then l
                mutations.append(gen_unconstrained_bit_field(
                    encoded_length, randint(1, min(self.MAX_OTA_RRC_PACKET_SIZE, max(1, l - 1)))))

                # Content is larger by OVERFLOW_LEN than length
                mutations.append(gen_unconstrained_bit_field(
                    encoded_length, min(self.MAX_OTA_RRC_PACKET_SIZE, l + self.OVERFLOW_LEN)))

            invalid_length_bytes = [generate_invalid_length_encoding()]
            invalid_length = int.from_bytes(invalid_length_bytes[0], 'big')
            mutations.append(gen_unconstrained_bit_field(
                invalid_length_bytes, 0))
            mutations.append(gen_unconstrained_bit_field(invalid_length_bytes, randint(
                1, min(self.MAX_OTA_RRC_PACKET_SIZE, max(1, invalid_length - 1)))))

            mutations.append(gen_unconstrained_bit_field(
                invalid_length_bytes, min(self.MAX_OTA_RRC_PACKET_SIZE, invalid_length + self.OVERFLOW_LEN)))

            return mutations

    def set_val_embedded(packet, target_path: list, value):
        if '*' not in target_path:
            return packet.set_val_at(target_path, value)
        logging.debug('Need to handle embedded field mutation')
        from itertools import groupby
        paths = [list(group) for key, group in groupby(
            target_path, lambda x: x == '*') if not key]

        current_packet = packet
        for p in paths[:-1]:

            current_packet.get_at(p)

            current_packet = RRCLTE_R17.GLOBAL.MOD['EUTRA-RRC-Definitions'][paths[1][0]]
            current_packet.from_uper(packet.get_val_at(paths[0]))

    def mutate_rrc_integer_field(self, packet, field: asnobj_str, target_path: list):
        """ Mutate an RRC INTEGER field. The field is mutated if the number of bits assigned to this field
        can represent smaller or larger values then the spec indicates. e.g if the field is 4 bit and constrained 
        to 0-14 according to the spec, the mutation will try values outside this range but within the 4 bit range.

        Args:
            field (RRC Obj): field to mutate

        Returns:
            str: bit string representing the mutated field
        """
      
        mutated_packets = []
        initial_packet_val = packet.get_val_at(target_path)
        p = deepcopy(packet._val)

        packet.set_val_at(target_path, initial_packet_val)
        range = field._const_val.root[0]
        length_bit_size = math.floor(math.log2(range.ub - range.lb)) + 1
        num = randint(range.lb, range.ub)
        packet.set_val_at(target_path, num)
        mutated_packets.append(packet.to_uper())

        # This has to be done in case the num is a default value that will remove the field from the packet
        packet.set_val(p)
        # Set to max possible value according to the number of bits available
        packet.set_val_at(
            target_path, (2**length_bit_size - 1) + range.lb)
        mutated_packets.append(packet.to_uper())
        packet.set_val_at(target_path, initial_packet_val)
    
        packet.set_val(p)
        # Overflow range
        packet.set_val_at(target_path, range.ub + 1)
        mutated_packets.append(packet.to_uper())

        # Reset packet to initial value
        packet.set_val_at(target_path, initial_packet_val)

        return mutated_packets
