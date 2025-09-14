from abstract_classes.fuzzer import Fuzzer
from nas.emm.emm_generator import EMMGenerator
from nas.emm.emm_stats import get_emm_target_field_count
from random import choice, randint
from pycrate_mobile import *
import logging
import threading

from utils.logging_config import setup_logging

from pycrate_mobile.NAS import *
from pycrate_mobile import *
from pycrate_core import *
from pycrate_csn1.csnobj import *

from nas.emm.emm_strategy import EMMStrategy
from nas.emm.emm_utils import flip_bits
import os
import sys

import random

field_lengths = {'EPSID': ('5', '12'), 'UENetCap': ('4', '15'), 'ESMContainer': ('3', 'n'), 'MSNetCap': ('4', '10'), 'MSCm3': ('2', '34'), 'SuppCodecs': ('5', 'n'), 'TAIList': ('8', '98'), 'ID': ('4', '10'), 'EquivPLMNList': ('5', '47'), 'EmergNumList': ('5', '50'), 'EPSNetFeat': ('3', '4'), 'ExtEmergNumList': ('7', '65538'), 'CipherKeyData': ('35', '2291'), 'NASContainer': ('3', '252'), 'RES': ('5', '17'), 'UESecCap': ('3', '6'), 'NASMessage': ('3', 'n'), 'NetFullName': ('3', 'n'), 'NetShortName': ('3', 'n'), 'CLI': ('3', '14'), 'LCSClientId': ('3', '257'), 'GenericContainer': ('3', 'n'), 'AddInfo': ('3', 'n')}


class EMMFuzzer(Fuzzer):

    ALL_STRATEGIES = [EMMStrategy.BASE, EMMStrategy.ADD, EMMStrategy.TAG, EMMStrategy.APPEND, EMMStrategy.FLIP, EMMStrategy.TRUNCATE]
   
    def __init__(self, seed=19, strategy=ALL_STRATEGIES, cycles=1, debug_mode=False) -> None:
        super().__init__(seed)
        self.cycles = cycles if cycles > 0 else sys.maxsize
        self.full_strategy = strategy
        self.strategy = strategy
        self.debug_mode = debug_mode
        
        # Enable debug logging if in debug mode
        if self.debug_mode:
            from utils.logging_config import setup_logging
            import logging
            setup_logging(level=logging.DEBUG)
            
        self.emm_generator = EMMGenerator(seed)
        self.total_target_fields = get_emm_target_field_count()
        self.searching = False

        # ADD is not a strategy but more like a generation addition
        if EMMStrategy.ADD not in self.strategy:
            self.strategy.append(EMMStrategy.ADD)
        # Add always 1 random field to the packet
        self.N = 1

    def get_strategy(self) -> list[EMMStrategy]:
        return self.strategy

    def get_coverage(self) -> float:
        return len(self.coverage_map) / self.total_target_fields
    

    def truncate_bytes(self, data: bytes, length: int) -> bytes:
        return data[:length]

    def mutate_packet(self, packet_type : EMMTypeMTClasses, packet_data: dict, target_field: str, optional_fields: list[str]) -> list[str]:
        """Generates mutations for a given packet data and a target field

        Args:
            packet_type (EMMTypeMTClasses): Type of the packet
            packet_data (dict): Key value pairs of packe data
            target_field (string): Name of the targeted field
            optional_fields (list[string]): List of optional fields in the packet

        Returns:
            mutations (list[str]): List of mutated packets
        """

        filtered_packet_data = self.filter_packet_data(
            packet_data, target_field, optional_fields)

        msg = packet_type(val=filtered_packet_data)
        msg_bytes = msg.to_bytes()
      
        # Base mutations
        basic_mutations = []

        if EMMStrategy.BASE in self.strategy:
            length_mutations = self.mutate_TLV_length(msg, target_field)
            internal_mutations = self.mutate_internal_length_field(
                msg, target_field)
            
            basic_mutations = length_mutations + internal_mutations
    
        # Tag mutations
        tag_mutations = []
        if EMMStrategy.TAG in self.strategy:
            # Both cases are considered as TAGs
            tag_mutations = self.mutate_TLV_tag(msg, target_field)
            if target_field == 'EMMHeader':
                tag_mutations.append(self.mutate_EMMHeader(msg))
        
        # Bit flip mutations
        flip_mutations = []
        if EMMStrategy.FLIP in self.strategy:
            flip_mutations.append(flip_bits(msg_bytes, flip_probability=0.02))

        # For each mutation, append a random number of bytes to the end of the packet
        append_mutations = []
        if EMMStrategy.APPEND in self.strategy:
            append_mutations.append(self.append_n_random_bytes(msg_bytes, n=100))

        # For each mutation, truncate a random number of bytes from the end of the packet
        truncate_mutations = []
        if EMMStrategy.TRUNCATE in self.strategy:
            truncate_mutations.append(self.truncate_bytes(msg_bytes, randint(min(2,len(msg_bytes)), len(msg_bytes))))
                
        return {'BASE' : basic_mutations, 'TAG' : tag_mutations, 'FLIP' : flip_mutations, 'APPEND' : append_mutations, 'TRUNCATE' : truncate_mutations} 


    def get_next_mutations(self) -> list[str]:
        """
        Gets the next generated packet from the generator and mutates it
        for every target field in the packet

        Returns:
            mutations (list[str]): List of mutated packets
        """
        if self.current_cycle > self.cycles:
            return None
        packet = self.emm_generator.get_next_packet()
        
        if packet is None:
            # Wait for all packets from previous cycle to be processed
            while(self.rollback_queue.qsize() > 0):
                pass

            self.current_cycle += 1
            if self.current_cycle > self.cycles:
                return None

            ## Prepare fuzzer for next cycle
            # Empty coverage map
            self.coverage_map = set()
            # Reset blacklist
            self.blacklist = set()
            # Get next packet, restart at the beginning of the cycle
            packet = self.emm_generator.get_next_packet()

        """
        For all fields in a generate packet target them and mutate them
        
        """
        _, ie, packet_type, optional_fields = packet

        all_mutations = []
        for target_field in ['EMMHeader'] + list(ie.keys()):
            # TODO Collect mutation type that was applied 
            mutations = self.mutate_packet(
                packet_type, ie, target_field, optional_fields)
            for (strategy, mutation) in mutations.items():
                if len(mutation) > 0:
                    all_mutations.append((mutation, packet_type()._name, target_field, strategy))

            # Add the packet_type and target field to the coverage map
            self.coverage_map.add((packet_type()._name, target_field))
        
        return all_mutations

    def fill_queue(self) -> None:
        """
        Fills the fuzzing queue with mutations
        Is meant to be run in a seperate thread
        This function is aimed to be run in a seperate thread

        Returns:
            None
        """
        while self.rollback_queue.qsize() < 500 and not self.finished():
            mutations = self.get_next_mutations()
            if mutations is None:
                return (None, None, None, None)

            for (mutation, packet_type, target_field, strategy) in mutations:
                logging.debug(f'Adding mutation to queue {packet_type} {target_field} {strategy}')
    
                for m in mutation:
                    if type(m) is list:
                       for m1 in m:
                           self.rollback_queue.put((m1, packet_type, target_field, strategy))
                    else:
                        self.rollback_queue.put((m, packet_type, target_field, strategy))

        self.searching = False

    def get_next_packet(self) -> tuple:
        """
        Get the next packet from the fuzzer. 
        Launches a thread to fill the queue if the size of queue is getting low and 
        the fuzzer is not finished
        Verifies that the packet is not blacklisted and adds it to the rollback stack

        Returns:
            bytes: next packet to be sent
            str: type of the packet
            str: target field of the packet
            str: strategy used to mutate the packet
        """

        if self.rollback_queue.qsize() < 50 and not self.finished() and not self.searching:
            self.searching = True
            t = threading.Thread(target=self.fill_queue).start()
        

        if self.finished():
            logging.debug('Finished fuzzing, no next packet')
            return None, None, None, None
        
        try:
            packet, packet_type, target_field, strategy = self.rollback_queue.get(timeout=0.5)
        except Exception as e:
            ## Try again in case of race condition between self.finished and queue empty
            logging.debug('Queue is empty trying again')
            return self.get_next_packet()



        # TODO change how blacklist works
        if self.is_blacklisted((packet_type, target_field, strategy)):
            return self.get_next_packet()
           
        return packet, packet_type, target_field, strategy

    def filter_packet_data(self, packet_data: dict, target_field: str, optional_fields: list[str]):
        """Filters the packet data by removing all none targeted optional fields

        Args:
            packet_data (dict): Message data
            target_field (string): Name of the targeted field
            optional_fields (list[string]): List of optional fields
            N (int): Number of random fields to add to the packet

        Returns:
            filtered_packet_data (dict): Filtered packet data
        """

        filtered_packet_data = {}
        for msg_field in packet_data:
            if msg_field == target_field or msg_field not in optional_fields:
                filtered_packet_data[msg_field] = packet_data[msg_field]

        # Add N random fields to the packet if the ADD strategy is enabled
        if EMMStrategy.ADD in self.strategy:
            random_fields = random.sample(
                optional_fields, min(self.N, len(optional_fields)))
            for field in random_fields:
                if field not in filtered_packet_data:
                    filtered_packet_data[field] = packet_data[field]

        return filtered_packet_data

    def select_target_field(self, packet_data: dict) -> str:
        """
        Selects a random field from the packet data

        Args:
            packet_data (dict): Key value pairs of packet data

        Returns:
            target_field (string): Name of the targeted field
        """
        return choice(list(packet_data.keys()))

    def mutate_EMMHeader(self, msg : EMMTypeMTClasses) -> list[bytes]:
        """Mutates the EMMHeader of a message

        Args:
            msg (EMMTypeMTClasses): Message data
        Returns:
            list[bytes]: List of mutated packets
        """
        mutations = []
        true_msg_type = msg['EMMHeader']['Type'].get_val()


        # TODO This seems to find a lot of crashes, increase from 2 to 10
        for _ in range(2):
            msg_type = randint(0, 255)
            if msg_type == true_msg_type:
                continue

            msg['EMMHeader']['Type'].set_val(msg_type)
            mutated_bytes = msg.to_bytes()
            mutations.append(mutated_bytes)

        # Reset the msg type
        msg['EMMHeader']['Type'].set_val(true_msg_type)

        return mutations

    def mutate_TLV_tag(self, msg : EMMTypeMTClasses, target_field_name : str) -> list[bytes]:
        """Mutates the tag of a TLV field

        Args:
            msg (EMMTypeMTClasses): Message data
            target_field_name (str): Name of the targeted field

        Returns:
            list[bytes]: List of mutated packets
        """

        target_field = msg[target_field_name]

        # Only mutate if the target field has a tag
        if type(target_field) not in (Type1TV, Type3TV, Type4TLV, Type6TLVE):
            return []

        mutations = []
        true_tag = target_field['T'].get_val()

        for _ in range(2):
            if type(target_field) == Type1TV:
                tag = randint(0, 2**4 - 1)
            else:
                tag = randint(0, 2**8 - 1)
            if tag == true_tag:
                continue

            target_field['T'].set_val(tag)
            mutated_bytes = msg.to_bytes()
            mutations.append(mutated_bytes)

        # Reset the tag
        target_field['T'].set_val(true_tag)

        return mutations

    def append_n_random_bytes(self, msg: bytes, n=100) -> bytes:
        """Appends n random bytes to the end of the message

        Args:
            msg (bytes): Message to append to
            n (int, optional): Number of bytes to append. Defaults to 100.

        Returns:
            bytes: Message with n random bytes appended
        """

        return msg + random.randbytes(n)

    def mutate_TLV_length(self, msg : EMMTypeMTClasses, target_field_name):
        """
        Mutates the length and value fields of a TLV field
        This mutations can be applied unconditionaly to any TLV field
        This strategy is used to mutate the Type fields that contain an IE

        Args:
            msg (EMMTypeMTClasses): Message to mutate
            target_field_name (string): name of the field to mutate

        Returns:
            mutations (list[bytes]): list of mutated messages
        """
        target_field = msg[target_field_name]
        target_bytes = target_field.to_bytes()
        length_field_size = 0
        MAX_TARGET_CONTENT_LENGTH = -1
        OVERFLOW_LEN = 500

        match type(target_field):
            case t if t in (Type4LV, Type6LVE):
                tag_field_size = 0
            case t if t in (Type4TLV, Type6TLVE):
                tag_field_size = 1
  
        match type(target_field):
            case t if t in (Type4TLV, Type4LV):
                MAX_TARGET_CONTENT_LENGTH = 2**8 - 1
                length_field_size = 1
            case t if t in (Type6TLVE, Type6LVE):
                # Should be 2**16 -1 but OTA communication is fixed to 2**11 - 1 max
                # TODO This is probably too much too
                MAX_TARGET_CONTENT_LENGTH = 2**16 - 1
                length_field_size = 2
            case _:
                return []
        
        # Check if the target has length constraints in the spec
        min_valid_len, max_valid_len = 0, -1
        if target_field_name in field_lengths:
            min_valid_len, max_valid_len = field_lengths[target_field_name]
            min_valid_len = max(0, int(min_valid_len, 10))
            if max_valid_len != 'n':
                max_valid_len = min(MAX_TARGET_CONTENT_LENGTH, int(max_valid_len, 10))

        if max_valid_len == -1 or max_valid_len == 'n':
            max_valid_len = MAX_TARGET_CONTENT_LENGTH

 
        mutations = []
        initial_target_content_length = target_field['L'].get_val()
        initial_target_content_bytes = target_bytes[tag_field_size + length_field_size:]

        def build_mutation(length : int, content : bytes) -> list[bytes]:
            """ Helper function to build a mutation

            Args:
                length (int): Length value of the mutated field
                content (bytes): Content of the mutated field

            Returns:
                list[bytes]: List of mutated messages
            """
            initial_message = msg.to_bytes()
            target_field['L'] = length
            mutations = []

            mutated_length_bytes = msg.to_bytes()  
            indices = []
            index = 0
            while True:
                index = mutated_length_bytes.find(initial_target_content_bytes, index)
                if index == -1:
                    break
                indices.append(index)
                index += len(initial_target_content_bytes)

            if len(indices) == 0:
                logging.error(f'Could not find target content in mutated bytes')
                logging.error(mutated_length_bytes)
                logging.error(initial_target_content_bytes)
            
            if len(indices) > 1:
                logging.debug(f'Found target content multiple times in mutated bytes')

            for i in indices:
                # Replace the content with random bytes
                mutated_length_and_content = mutated_length_bytes[:i] + content + \
                    mutated_length_bytes[i + len(initial_target_content_bytes):]
                mutations.append(mutated_length_and_content)
            
            if len(content) == len(initial_target_content_bytes):
                assert len(mutated_length_and_content) == len(initial_message)

            # Reset content length
            target_field['L'] = initial_target_content_length

            assert msg.to_bytes() == initial_message
            return mutations
        # Different mutations

        # Length 0, with unmodified content
        mutations += build_mutation(0, initial_target_content_bytes)

        # Random length within bounds, with unmodified content
        mutations += build_mutation(randint(0, MAX_TARGET_CONTENT_LENGTH), initial_target_content_bytes)

        # TODO Might be the same as the mutation above
        # Length min valid length, with content of length min valid length - 1 or 0
        mutations += build_mutation(max(0,min_valid_len), initial_target_content_bytes[:max(0,min_valid_len - 1)])

        # Max possible content length, with unmodified content
        mutations += build_mutation(MAX_TARGET_CONTENT_LENGTH, initial_target_content_bytes)

        # Maximum valid length + 1, with unmodified content
        mutations += build_mutation(min(max_valid_len + 1, MAX_TARGET_CONTENT_LENGTH), initial_target_content_bytes)

        # Random content length between 0 and maximum valid length of the field
        mutations += build_mutation(randint(min_valid_len, max_valid_len), initial_target_content_bytes)

        # Overflow content by OVERFLOW_LEN by appending bytes to target field
        content = initial_target_content_bytes + random.randbytes(OVERFLOW_LEN + initial_target_content_length)
        mutations += build_mutation(1, content)
      
        l = randint(min_valid_len, max_valid_len)
        mutations += build_mutation(l, content)


        return mutations
     
    def mutate_internal_length_field(self, msg, target_field_name):
        """ 
        Mutates specific fields internal to the target field
        Mutations are applied only if the target field contains implicit fields that represent
        a content length and a length

        Args:
            msg (pycrate_mobile.TS24301_EMM.EMMTypeMTClasses): Message to mutate
            target_field_name (string): name of the field to mutate

        Returns:
            mutations (list[bytes]): list of mutated packets
        """
        target_field = msg[target_field_name]
        target_field_value = target_field.get_val()
     
        mutations = []

        match target_field_name:
            case 'CipherKeyData':

                logging.debug('CipherKeyData')
                cipher_key_data_seq = target_field[2]

                if len(target_field_value[2]) == 0:
                    return []

                elem_index = randint(0, len(target_field_value[2]) - 1)
                cipher_key_data_element = cipher_key_data_seq[elem_index]
                c0_length = cipher_key_data_element[3]
                c0_content = cipher_key_data_element[4]
                initial_length = c0_length.get_val()
                initial_content = c0_content.get_val()

                # Length set to maxiumum value
                c0_length.set_val(31)
                mutations.append(msg.to_bytes())

                # Length set to 0
                c0_length.set_val(0)
                mutations.append(msg.to_bytes())

                # Length set to 1 and content set to 255 bytes
                c0_content.set_val(random.randbytes(255))
                msg.reautomate()
                c0_length.set_val(1)
                mutations.append(msg.to_bytes())

                # Reset values
                c0_length.set_val(initial_length)
                c0_content.set_val(initial_content)
                msg.reautomate()

            case 'ExtEmergNumList':
                logging.debug('ExtEmergNumList')
                ext_emerg_num_list_value = target_field_value[2][2]
                if len(ext_emerg_num_list_value) == 0:
                    return []

                ext_emerg_num_list = target_field[2][2]

                # Pick random element to mutate
                elem_index = randint(0, len(ext_emerg_num_list_value) - 1)
                ext_emerg_num_list_element = ext_emerg_num_list[elem_index]

                len_num = ext_emerg_num_list_element[0]
                content_num = ext_emerg_num_list_element[1]
                len_subservices = ext_emerg_num_list_element[2]
                content_subservices = ext_emerg_num_list_element[3]

                initial_len_num = len_num.get_val()
                initial_content_num = content_num.get_val()

                """
                Num field mutations
                """
            
                # Length_num set to maxiumum value
                len_num.set_val(255)
                mutations.append(msg.to_bytes())

                # Length_num set to 0
                len_num.set_val(0)
                mutations.append(msg.to_bytes())

                # Length_num set to 1 and num set to 255 bytes
                content_num.set_val(b'A'*255)
                msg.reautomate()
                len_num.set_val(1)
                mutations.append(msg.to_bytes())

                """
                Subservices field mutations
                """

                # Reset length_num and num
                len_num.set_val(initial_len_num)
                content_num.set_val(initial_content_num)
                msg.reautomate()

                initial_len_subservices = len_subservices.get_val()
                initial_content_subservices = content_subservices.get_val()

                # Lengh_subservices set to maxiumum value
                len_subservices.set_val(255)
                mutations.append(msg.to_bytes())

                # Lengh_subservices set to 0
                len_subservices.set_val(0)
                mutations.append(msg.to_bytes())

                # Lengh_subservices set to 1 and subservices set to 255 bytes
                content_subservices.set_val(random.randbytes(255))
                # Fix outer message length
                msg.reautomate()
                len_subservices.set_val(1)
                mutations.append(msg.to_bytes())

                # Reset length_subservices and content_subservices
                len_subservices.set_val(initial_len_subservices)
                content_subservices.set_val(initial_content_subservices)
                msg.reautomate()

            case 'TAIList':
                # Does this even make sense to mutate
                logging.debug('TAIList')
                index = next((index for index, item in enumerate(
                    target_field_value) if isinstance(item, list)), -1)
                for i, e in enumerate(target_field_value[index]):
                    # Mutate the 'Num' field in PartialTAIList0 and PartialTAIList2
                    if len(e) == 4 or type(e[-1]) is list:
                        # Set Num to 0
                        initial_value = target_field[index][i][2].get_val()
                        target_field[index][i][2].set_val({'Num': 0})

                        mutations.append(msg.to_bytes())

                        target_field[index][i][2].set_val({'Num': 1})
                        mutations.append(msg.to_bytes())

                        # Reset value
                        target_field[index][i][2].set_val(initial_value)

            case 'EmergNumList':
                logging.debug('EmergNumList')
                mutations = []

                initial_length = target_field[2][0][0].get_val()
                initial_content = target_field[2][0][-1].get_val()
                # Set length to 0
                target_field[2][0][0].set_val(0)
                mutations.append(msg.to_bytes())
                target_field[2][0][0].set_val(initial_length)

                # Set length to max value (255) and content to length 0
                target_field[2][0][-1].set_val(b'')
                msg.reautomate()
                target_field[2][0][0].set_val(255)
                # Fix outer length value

                mutations.append(msg.to_bytes())

                # Reset length and content
                target_field[2][0][0].set_val(initial_length)
                target_field[2][0][-1].set_val(initial_content)
                # Fix outer length value
                msg.reautomate()


            case _:
                pass

        return mutations
