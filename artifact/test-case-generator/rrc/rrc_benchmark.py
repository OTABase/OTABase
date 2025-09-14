from rrc.rrc_generator import RRCGenerator
from rrc.rrc_fuzzer import RRCFuzzer, RRCStrategy
from rrc.rrc_fields import Fields

import time
import logging

def benchmark_rrc_generation():
    """ Benchmark the generation of RRC packets """
    rrc_generator = RRCGenerator(
        targets=[Fields.BIT_STRING, Fields.OCTET_STRING])
    total_time = 0
    ntests = 500
    for i in range(ntests):
        start_time = time.time()
        m = rrc_generator.generate_packet()
        end_time = time.time()
        total_time += (end_time - start_time)

    logging.info(
        f"Average execution time: {total_time / ntests} seconds")


def benchmark_rrc_mutations(ntests=1, targets=[Fields.BIT_STRING, Fields.OCTET_STRING], strategies=[RRCStrategy.BASE]):
    """ Benchmark the generation of RRC mutations """
    rrc_fuzzer = RRCFuzzer(targets=targets, strategies=strategies)
    total_time = 0
    tot_len = 0
    for _ in range(ntests):
        start_time = time.time()
        _, m = rrc_fuzzer.get_packet_mutations()
        if m is None:
            logging.info('All paths covered')
            return
        tot_len += len(m)
        end_time = time.time()
        total_time += (end_time - start_time)

    logging.info(
        f"Average execution time: {total_time / ntests} seconds")

    logging.info(
        f"Execution time pper mutation: {total_time / tot_len} seconds")
