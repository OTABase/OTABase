from abstract_classes.generator import Generator
from rrc.releaseLTE_R17 import RRCLTE_R17
from rrc.rrc_choices import get_choices
from rrc.rrc_fields import Fields
from rrc.rrc_stats import get_recursif_field_paths
from rrc.rrc_fields import Fields

import logging
import os
import random

class RRCGenerator(Generator):
    """
    Class for generating RRC messages

    Attributes:
        targets (list(Fields)): List of target fields
        max_recur_depth (int): Maximum recursion depth, default is 0
        seed (int): Seed for random number generation, default is 20
        optional (bool): Enable optional fields, default is True
    """
    OCTET_STRING_LENGTH = 32
    BIT_STRING_LENGTH = 64

    def __init__(self, targets: list, max_recur_depth=0, seed=20, optional=True) -> None:
        super().__init__(seed) 
        self.targets = targets
        self.optional = optional
        self.bb = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message

        self.recursif_fields = list(
            map(lambda x: x[-1], get_recursif_field_paths(self.targets)))
        self.max_recur_depth = max_recur_depth

        # For each target field, get the path to the target field and the sequence of choices to reach the target field
        _, _, choice_paths = get_choices(self.bb, targets=self.targets)

        # Collect all the paths to the choices
        self.choice_paths = [(choices[:-1], paths[1:])
                             for (choices, paths) in choice_paths]
        
        self.choice_index = 0
        
        
        tmp = []
        for (choices, full_path) in self.choice_paths:
            # Remove the SEQOF element
            while ('_item_' in full_path):
                full_path.remove('_item_')

            full_path = [
                item for item in full_path if not item.startswith('_cont_')]
            tmp += [(choices, full_path)]
        
        self.choice_paths = tmp
        self.current_choice_path = []
        self.found_paths = set()
        self.choices = set()
        self.next_choice_path_generator = self.get_next_choice_path_generator()
      
    def add_to_found(self, path: list) -> None:
        """ 
        Adds a path to the found paths set
        This can be used by the fuzzer to speed up generation of new target fields

        Args:
            path (list(str)): The path to add
        """
        self.found_paths.add(tuple(path))

        # with open('found_paths.txt', 'w') as f:
        #     f.write(str(self.found_paths))
        return

    def reset_found(self) -> None:
        """ 
        Resets the found paths set and the choices set
        """
        self.found_paths = set()
        self.choices = set()
        self.choice_index = 0
        return

    def get_next_choice_path_generator(self):
        """ 
        Returns a generator that yields the next choice path
        that was not yet explored.
        It uses the set of found paths and the set of choices to
        determine which path to yield next.

        Yields:
            list(str): List of consecutive choices to take during generation
        """
        while (True):
            self.choice_index = (self.choice_index + 1)
            self.choice_index = self.choice_index % len(self.choice_paths)
            choices, full_path = [], []
            while True:
               
                choices, full_path = self.choice_paths[self.choice_index - 1]

                # Avoid going the down the same path and avoid going down the same choices
                if tuple(full_path) not in self.found_paths and tuple(choices) not in self.choices:
                    self.choices.add(tuple(choices))
                    break
                self.choice_index += 1

            yield choices.copy()

    def get_unique_path(self, paths):
        """
        Get unique paths from a list of paths

        Args:
            paths (list): List of paths to process

        Returns:
            set: Set of unique paths
        """
        unique_paths = set()
        for path in paths:
            unique_paths.add(tuple(
                [x for x in path if not isinstance(x, int)]))

        return unique_paths

    def loop_IE(self, bb, choice_path=[], curr_path=[], targets=[], recur_depth=0):
        """
        Recursively generate RRC message elements

        Args:
            bb (ASN1Object): The current ASN.1 element being processed
            choice_path (list): List of choices for CHOICE elements
            curr_path (list): Current path in the message structure
            targets (list): List of target fields
            recur_depth (int): Current recursion depth
        """

        if bb._name == 'DL-DCCH-Message':
            assert len(self.current_choice_path) == 0
            choice_path = self.next_choice_path_generator.__next__()

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
                logging.error('Empty sequence')

            one_ie = {}
            optional_paths = []
            tot_optional_paths = []
            tot_mutation_paths = []

            # Optional fields
            if bb._opt:
                logging.debug(f'Sequence is optional : {bb._opt}')
                optional_paths.append(curr_path)

            items = [t[0] for t in list(bb._cont.items())]
            for ie_name in items:

                # Ignores all the optional fields
                if ie_name in bb._root_mand or self.optional:

                    gen, rec_mutation_paths, rec_optional_paths = self.loop_IE(
                        bb._cont[ie_name], choice_path.copy(), [*curr_path, ie_name], targets, recur_depth=recur_depth)

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

            # The choice options
            options = list(bb._cont.keys())
            logging.debug(options)

            optional_paths = []
            if bb._opt:
                optional_paths.append(curr_path)

            if len(choice_path) == 0:
                # If the choice path is empty, pick a random element
                # Make sure that choices leading to target fields are visited
                next_ie = random.choice(options)
            else:
                next_ie = choice_path[0]

            # Check that next_ie is in options
            if next_ie not in options:
                # If the next_ie is not in the options, select a random one
                # Make sure that choices leading to target fields are visited
                next_ie = random.choice(options)
            elif len(choice_path) > 0:
                choice_path.pop(0)

            rand_ie = next_ie

            gen, rec_mutation_paths, rec_optional_paths = self.loop_IE(
                bb._cont[rand_ie], choice_path.copy(), [*curr_path,  rand_ie], targets, recur_depth=recur_depth)
            rec_mutation_paths = [p for p in rec_mutation_paths if p]

            return (rand_ie, gen), rec_mutation_paths, optional_paths + rec_optional_paths

        if (bb.TYPE == 'INTEGER'):
            logging.debug('INTEGER')

            # Default value is replaced here
            ie_range = bb._const_val.root[0]

            mutation_paths = []
            if type(ie_range) == int:
                # Integer is constant
                ie_lb = ie_range
                ie_ub = ie_range
            else:
                ie_lb = ie_range.lb
                ie_ub = ie_range.ub
            optional_paths = []
            if bb._opt:
                logging.debug('Optional Integer')
                optional_paths.append(curr_path)
            # Pick random value between lb and ub
            r = ie_ub - ie_lb + 1

            # Range size is not a power of 2
            if r & (r - 1) != 0 and Fields.INTEGER in targets:
                mutation_paths.append(curr_path)

            return random.randint(ie_lb, ie_ub), mutation_paths, optional_paths

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
            logging.debug(bb._root)
            logging.debug(bb._name)

            mutation_path = []
            optional_paths = []

            if bb._opt:
                logging.debug('OCTET STRING IS OPTIONAL')
                optional_paths.append(curr_path)

            if bb._const_cont is not None:

                if bb._name in self.recursif_fields:
                    # When the recursif depth is reached, do not expand using format definition
                    if recur_depth == self.max_recur_depth:
                        logging.debug('Max recusrif depth reached')
                        logging.debug(
                            'Stop recursif expansion for ', bb._name)
                        return b'a', [], optional_paths

                    recur_depth = recur_depth + 1

                container = RRCLTE_R17.GLOBAL.MOD['EUTRA-RRC-Definitions'][bb._const_cont.get_type_list()[
                    0]]

                ie, rec_mutation_paths, rec_optional_paths = self.loop_IE(
                    container, choice_path.copy(), curr_path, targets, recur_depth=recur_depth)
                logging.debug(ie)
                logging.debug(bb._name)

                embedded_mutation_paths = []
                # Insert '*' to remember where the container starts
                for m in rec_mutation_paths:
                    embedded_mutation_paths.append(
                        curr_path + ['*', bb._const_cont.get_type_list()[0]] + m[len(curr_path):])

                for o in rec_optional_paths:
                    optional_paths.append(
                        curr_path + ['*', bb._const_cont.get_type_list()[0]] + o[len(curr_path):])

                container.set_val(ie)

                if Fields.OCTET_STRING in targets:
                    mutation_path = curr_path

                return bytes.fromhex(container.to_uper().hex()), [mutation_path] + embedded_mutation_paths, optional_paths

            if Fields.OCTET_STRING in targets:
                mutation_path = curr_path

            # Length is bound
            if (bb._const_sz != None):
                oct_str_len = random.randint(bb._const_sz.lb, bb._const_sz.ub)

                # Length can take a single value, no need to mutate as the length is not present in the message encoding
                if bb._const_sz.lb == bb._const_sz.ub:
                    mutation_path = []
            else:
                # Choose long enough content to uniquely identify it during mutation
                oct_str_len = self.OCTET_STRING_LENGTH

            return bytes(random.getrandbits(8) for _ in range(oct_str_len)), [mutation_path], optional_paths

        if (bb.TYPE == 'BIT STRING'):
            logging.debug('BIT STRING')

            optional_paths = []
            if bb._opt:
                optional_paths.append(curr_path)

            if bb._const_cont is not None:
                logging.debug('Found not None continuation for BIT STRING')
                exit(0)

            mutation_path = []
            if Fields.BIT_STRING in targets:
                mutation_path = curr_path

            if (bb._const_sz != None):
                logging.debug(f'Upper bound {bb._const_sz.ub}')
                logging.debug(f'Lower bound {bb._const_sz.lb}')
                bit_str_len = random.randint(bb._const_sz.lb, bb._const_sz.ub)

                # Length can take a single value, no need to mutate
                if bb._const_sz.lb == bb._const_sz.ub:
                    mutation_path = []
            else:
                # Choose long enough content to uniquely identify it during mutation
                bit_str_len = self.BIT_STRING_LENGTH

            return (random.getrandbits(bit_str_len), bit_str_len), [mutation_path], optional_paths

        if (bb.TYPE == 'SEQUENCE OF'):

            if bb._name == '_item_' and bb._tr is not None:
                curr_path = curr_path + ['^', bb._tr._name]

            optional_paths = []
            if bb._opt:
                optional_paths.append(curr_path)

            temp = []
            mutation_paths = []

            n_elem = random.randint(bb._const_sz.lb, bb._const_sz.ub)

            # Generate the smallest message possible with at least one element
            n_elem = bb._const_sz.lb
            if bb._const_sz.lb == bb._const_sz.ub:

                n_elem = bb._const_sz.lb
            else:
                n_elem = bb._const_sz.lb + 1

            logging.debug(f'Number of elements : {n_elem}')

            for i in range(n_elem):
                gen, rec_mutation_paths, rec_optional_paths = self.loop_IE(
                    bb._cont,
                    choice_path.copy(),
                    [*curr_path, '__elem__', i],
                    targets,
                    # [*curr_path, bb._name, i] Old value
                    recur_depth=recur_depth)

                temp.append(gen)
                mutation_paths += rec_mutation_paths
                optional_paths += rec_optional_paths

            logging.debug(mutation_paths)
            logging.debug(optional_paths)

            mutation_path = None
            if Fields.SEQOF in targets and bb._const_sz.lb != bb._const_sz.ub:
                # Calculate the range size
                r = bb._const_sz.ub - bb._const_sz.lb + 1
                # Only add mutation path if range size is not a power of 2
                if r & (r - 1) != 0:
                    mutation_path = curr_path

            return temp, [p for p in [mutation_path] + mutation_paths if p], optional_paths

    def generate_packet(self):
        """
        Generates an RRC packet and collects the list of mutation paths and optional paths
        that can be used to mutate the packet.

        Returns:
            fuzz_result     : UPER encoded packet
                                the generated packet in UPER format.
            result          : dict
                                the generated packet in dict format.
            mutation_paths  : list
                                list of mutation paths.
            optional_paths  : list
                                list of optional paths.
        """

        gen_result = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message
        result, mutation_paths, optional_paths = self.loop_IE(
            self.bb, targets=self.targets)

        logging.debug('\n' * 2)
        logging.debug('-------------- Packet --------------')
        logging.debug(result)
        logging.debug('-------------- Mutation paths --------------')
        logging.debug(mutation_paths)
        logging.debug('-------------- Optional paths --------------')
        logging.debug(optional_paths)

        # logging.info('Returning generated packet')
        try:
            gen_result.set_val(result)
        except Exception as e:
            logging.error("error: ", e)
            os._exit(0)

        logging.debug('Generated packet: ' + str(gen_result.to_uper().hex()))
        return gen_result.to_uper(), result, mutation_paths, optional_paths

    def get_packet_generator(self):
        """
        Get a generator for RRC packets

        Returns:
            generator: A generator that yields generated RRC packets
        """

        yield self.generate_packet()
