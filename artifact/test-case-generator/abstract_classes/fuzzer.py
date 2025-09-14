from abc import *
from utils.rollback_queue import RollbackQueue
import random
import sys
import threading

class Fuzzer(ABC):
    """
    Abstract class for fuzzers

    """

    def __init__(self, seed, cycles=1, blacklist=True) -> None:
        """
        Constructor for the fuzzer

        """
        self.seed = seed
        # self.randomness = random.Random(seed)
        random.seed(seed)
        self.rollback_queue = RollbackQueue()
        self.rollback_queue_lock = threading.Lock()
        self.blacklist = None
        if blacklist:
            self.blacklist = set()
        self.coverage_map = set()

        self.cycles = cycles if cycles > 0 else sys.maxsize
        self.current_cycle = 1

    @abstractmethod
    def get_coverage(self) -> float:
        """
        Returns the coverage of the fuzzer between 0 and 1

        Returns:
            float: coverage of the fuzzer
        """
        pass

    def finished(self) -> bool:
        """
        Check if the fuzzer is finished

        Returns:
            bool: True if the fuzzer is finished
        """
        return self.rollback_queue.empty() and self.get_coverage() == 1 \
            and self.current_cycle > self.cycles

    @abstractmethod
    def get_next_packet(self) -> tuple:
        """
        Get the next packet from the fuzzer

        Returns:
            tuple: next packet
        """
        pass

    def rollback(self, amount: int) -> None:
        """
        Rollback the fuzzer to a given packet

        Args:
            amount (int): amount to rollback
        """
        self.rollback_queue.rollback(amount)

    def get_last_n(self, n: int) -> list:
        return self.rollback_queue.get_last_n(n)

    def add_blacklist(self, target_field: tuple) -> None:
        """
        Blacklist a target field

        Args:
            target_field (tuple): target field to blacklist
        """
        self.blacklist.add(target_field)

    def is_blacklisted(self, target_field: tuple) -> bool:
        """
        Check if a target field is blacklisted

        Args:
            target_field (tuple): target field to check
        """
        return target_field in self.blacklist    

    def get_cycle(self) -> int:
        """
        Get the current cycle of the fuzzer

        Returns:
            int: current cycle of the fuzzer
        """
        return self.current_cycle
    
