from pycrate_csn1.csnobj import *

from abstract_classes.generator import Generator
from random import randint
from nas.nas_utils import random_dic_index
import logging

from utils.logging_config import setup_logging


class CSN1Generator(Generator):
    """ CSN generator for MSNetCap and MSCm3 fields
    Implements the Generator abstract class

    Args:
        csn_root (CSN1Obj): Root of the CSN1 object tree

    """

    def __init__(self, csn_root):
        self.csn_root = csn_root

    def get_packet_generator(self):

        def generate_CSN_data(csn):
            """Generates random data for a CSN1 object

            Args:
                csn (CSN1Obj): CSN1 object

            Returns:
                res (list): Random valid data for the CSN1 object
            """
            logging.debug('In csn matching')
            match csn:
                case c if type(c) is CSN1List:
                    res = []
                    for i in c._list:
                        res.append(self.generate_CSN_data(i))
                    return res

                case c if type(c) is CSN1Bit:
                    # spare bits
                    if c._num == -1:
                        return []

                    return randint(0, 2**c._bit - 1)

                case c if type(c) is CSN1Ref:
                    if c._num > 1:
                        return [self.generate_CSN_data(c._obj) for i in range(c._num)]
                    return self.generate_CSN_data(c._obj)

                case c if type(c) is CSN1Alt:
                    index = random_dic_index(c._alt)
                    res = [index]

                    for i in c._alt[index][1]:
                        res.append(self.generate_CSN_data(i))

                case _:
                    logging.error('CSN type not found')
                    exit(0)

            return res

        yield generate_CSN_data(self.csn_root)
