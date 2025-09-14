from queue import Queue
from threading import Lock


class RollbackQueue:
    """
    A queue that supports rollback to a previous state

    The total queue_size is queue_size + rollback_size
    """

    def __init__(self, rollback_size=50):
        self.queue = Queue()
        self.rollback_stack = []
        self.lock = Lock()
        self.rollback_size = rollback_size

    def put(self, item):
        self.queue.put(item)

    def get(self, timeout=None):
        item = self.queue.get(timeout=timeout)
        return item
    
    def add_to_rollback_stack(self, item):
        with self.lock:
            self.rollback_stack.append(item)
            if len(self.rollback_stack) > self.rollback_size:
                self.rollback_stack.pop(0)

    def rollback(self, n_elem: int) -> bool:
        """Rollback the queue by n_elem
        This operation is rare and thus performance is not a concern

        Args:
            n_elem (any): number of elements to rollback
        """
        if n_elem > len(self.rollback_stack):
            return False

        temp_queue = Queue()
        with self.lock:

            # Add the rollbacked items back to the queue
            for elem in self.rollback_stack[-n_elem:]:
                temp_queue.put(elem)

            # Remove the rollbacked items from the rollback stack
            self.rollback_stack = self.rollback_stack[:-n_elem]

        while not self.queue.empty():
            temp_queue.put(self.queue.get())

        self.queue = temp_queue

        return True

    def qsize(self):
        return self.queue.qsize()

    def get_last_n(self, n):
        """Get the last popped item from the queue

        Returns:
            any: last popped item
        """
        if len(self.rollback_stack) < n:
            return None
        return self.rollback_stack[-n:]

    def empty(self):
        return self.queue.empty()


def main():

    rollback_queue = RollbackQueue(rollback_size=5)

    for i in range(10):
        rollback_queue.put(i)

    # Remvoe 3 items (0, 1, 2)
    rollback_queue.get()
    rollback_queue.get()
    rollback_queue.get()
    rollback_queue.get()
    rollback_queue.get()

    rollback_queue.rollback(3)

    print(list(rollback_queue.queue.queue))

    print(rollback_queue.get())


if __name__ == '__main__':
    main()