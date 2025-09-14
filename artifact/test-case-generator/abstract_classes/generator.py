from abc import ABC, abstractmethod
import random


class Generator(ABC):
    """
    Abstract class for generators

    """

    def __init__(self, seed):
        self.seed = seed
        random.seed(seed)
        # self.randomness = random.Random(seed)
        self.generator = self.get_packet_generator()

    """
    Get the generator function
    
    Returns:
        generator: generator function
    
    """
    @abstractmethod
    def get_packet_generator(self):
        pass

    """
    Get the next packet from the generator

    Returns:
        The value returned by the generator function

    """

    def get_next_packet(self):
        return self.generator.__next__()
