from rrc.rrc_fuzzer import RRCFuzzer, RRCStrategy
from rrc.rrc_fields import Fields
from rrc.rrc_controller import RRCController
from rrc.rrc_generator import RRCGenerator
from rrc.rrc_benchmark import benchmark_rrc_generation, benchmark_rrc_mutations
from rrc.rrc_stats import get_target_field_count


import pandas as pd

import os
import random
import argparse
import time


def calculate_average(numbers):
    if not numbers:
        return 0.0
    total = sum(numbers)
    average = total / len(numbers)
    return average


def parse_target_fields(field_names):
    """Convert string field names to Fields enum values"""
    field_mapping = {
        'BIT_STRING': Fields.BIT_STRING,
        'OCTET_STRING': Fields.OCTET_STRING,
        'INTEGER': Fields.INTEGER,
        'SEQOF': Fields.SEQOF
    }
    
    target_fields = []
    for field_name in field_names:
        if field_name in field_mapping:
            target_fields.append(field_mapping[field_name])
        else:
            raise ValueError(f"Unknown field type: {field_name}")
    
    return target_fields


def test_generator(times=1):
    """
    For 50 seeds

    Old values
    Average time taken 25.119423985481262
    Minimum time taken 8.25641679763794
    Maximum time taken 55.06851005554199

    New values
    Average time taken 2.2537522411346433
    Minimum time taken 1.916565179824829
    Maximum time taken 3.0419766902923584

    """
    all_times = []
    for s in [random.random() for _ in range(times)]:
        targets = [Fields.SEQOF]
        rrc_generator = RRCGenerator(targets=targets, seed=s)

        target_count = get_target_field_count(targets=targets, w_recur=False)

        print(f'T count is {target_count}')
        coverage_map = set()

        all_paths = set()
        start_time = time.time()

        while (True):

            _, _, mutation_paths, _ = rrc_generator.generate_packet()

            print('Got new packet')

            old_coverage = len(coverage_map)
            for path in mutation_paths:

                all_paths.add(tuple(path))
                # with open("all_generated_mut_paths.txt", 'w') as f:
                #         f.write(str(list(all_paths)))
                # Remove SEQOF index for coverage computation
                unique_path = tuple(
                    [x for x in path if not isinstance(x, int)])

                if unique_path not in coverage_map:
                    rrc_generator.add_to_found(unique_path)
                    coverage_map.add(unique_path)

                    print(f'Coverage: {len(coverage_map)}/{target_count}')

            if len(coverage_map) == target_count:
                # print('Finished')
                break
        rrc_generator.reset_found()
        end_time = time.time()

        print(f'Time taken {end_time - start_time}')
        all_times.append(end_time - start_time)
    print(f'Average time taken {sum(all_times)/len(all_times)}')
    print(f'Minimum time taken {min(all_times)}')
    print(f'Maximum time taken {max(all_times)}')

    """
    Average time taken 10.458692717552186
    Minimum time taken 7.300771474838257
    Maximum time taken 14.729581832885742
    """

def test_fuzzer(cycles, seed):
    payloads = {}

    # targets = [Fields.SEQOF]
    targets = [Fields.SEQOF, Fields.OCTET_STRING,
               Fields.BIT_STRING, Fields.INTEGER]
    rrc_fuzzer = RRCFuzzer(cycles=cycles, strategies=[
                           RRCStrategy.BASE, RRCStrategy.TRUNCATE, RRCStrategy.ADD], targets=targets, seed=seed, debug_mode=False)
    i = 0
    start_time = time.time()
    delays = []
    time_between_packet = time.time()

    total_coverage = get_target_field_count(targets=targets)
    stats_df = pd.DataFrame(
        columns=['packet_num_mut', 'packet_num_field', 'time', 'cycle', 'total_coverage'])
    current_cycle = 1

    target_field_paths = set()

    while (True):

        if rrc_fuzzer.get_cycle() != current_cycle:
            target_field_paths = set()
            current_cycle = rrc_fuzzer.get_cycle()

        rrc_packet, path, _ = rrc_fuzzer.get_next_packet()
        if rrc_packet == None:
            print(f'Number of test payloads {i}')
            break

        i += 1

        target_field_paths.add(tuple(path))
        delays.append(time.time() - time_between_packet)
        time_between_packet = time.time()
        print(rrc_fuzzer.get_coverage())

        new_df = pd.DataFrame({'packet_num_mut': [i],
                               'packet_num_field': [len(target_field_paths)],
                               'time': [time.time()],
                               'cycle': [current_cycle],
                               'total_coverage': [total_coverage]})

        stats_df = pd.concat([stats_df, new_df])

    print(rrc_fuzzer.get_coverage())
    print(f'Time taken {time.time() - start_time}')
    print('Finished fuzzer test')

    # Save df to csv file
    stats_df.to_csv('rrc_fuzzing_stats.csv', index=False)

    print(delays)
    print(calculate_average(delays))
    print(f'Number of test payloads {i}')

    return


def main():
    # Prev def seed was 19
    DEFAULT_SEED = 1
    DEFAULT_CYCLES = 1
    DEFAULT_OUTPUT_FILENAME = 'payloads/rrc/rrc_payloads.txt'

    # Read cmd line args
    parser = argparse.ArgumentParser(description='Run the EMM fuzzer')
    parser.add_argument('-t', '--test', type=str,
                        choices=['gen', 'fuzz', 'benchmark', 'find'], help='Test NAS EMM Fuzzer')
    parser.add_argument('-c', '--cycles', type=int,
                        help='Number of cycles to run the fuzzer for')
    parser.add_argument('-o', '--output_filename',
                        type=str, help='Output filename')
    parser.add_argument('-s', '--seed', type=int, help='Seed for the fuzzer')
    parser.add_argument('-f', '--fields', type=str, nargs='+', 
                        choices=['BIT_STRING', 'OCTET_STRING', 'INTEGER', 'SEQOF'],
                        default=['OCTET_STRING'],
                        help='Target fields for fuzzing (default: OCTET_STRING)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable debug mode (saves coverage files)')

    args = parser.parse_args()

    if args.seed is None:
        args.seed = DEFAULT_SEED

    if args.output_filename is None:
        args.output_filename = DEFAULT_OUTPUT_FILENAME

    if args.cycles is None:
        args.cycles = DEFAULT_CYCLES

    if args.test == 'fuzz':
        test_fuzzer(args.cycles, args.seed)
    elif args.test == 'gen':
        test_generator()
    elif args.test == 'benchmark':
        benchmark_rrc_generation()
        benchmark_rrc_mutations()
    else:

        # Check if the file exists, else create an empty file
        if not os.path.exists(args.output_filename):
            open(args.output_filename, 'w').close()
            

        # Parse target fields from command line
        target_fields = parse_target_fields(args.fields)
        field_names = [field.name for field in target_fields]
        print(f"Targeting fields: {', '.join(field_names)}")
        
        if args.debug:
            print("Debug mode enabled - coverage files will be saved and debug logging enabled")
            from utils.logging_config import setup_logging
            import logging
            setup_logging(level=logging.DEBUG)
        
        # Run the fuzzer
        rrc_fuzzer = RRCFuzzer(targets=target_fields, strategies=[
                               RRCStrategy.BASE, RRCStrategy.TRUNCATE], cycles=args.cycles, seed=args.seed, debug_mode=args.debug)
        rrc_controller = RRCController(
            fuzzer=rrc_fuzzer, output_file_name=args.output_filename)
        rrc_controller.start_server()


if __name__ == '__main__':
    main()
