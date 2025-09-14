from nas.emm.emm_controller import EMMController, EMMOracleType
from nas.emm.emm_fuzzer import EMMFuzzer
from nas.emm.emm_generator import EMMGenerator
from utils.logging_config import setup_logging

import pandas as pd
import time
import random
import argparse
import os

# Setup logging and ensure INFO level
setup_logging()
# Ensure INFO level in case other libraries changed it
from utils.logging_config import ensure_info_level
ensure_info_level()

# Helper function for calculating average


def calculate_average(numbers):
    if not numbers:
        return 0.0
    total = sum(numbers)
    average = total / len(numbers)
    return average

# Test function for EMM generator


def test_generator():
    times = []
    for _ in range(5):
        emm_generator = EMMGenerator(seed=1)
        start_time = time.time()
        while True:
            p = emm_generator.get_next_packet()
            if p is None:
                break
        end_time = time.time()
        logging.debug(f'Time taken {end_time - start_time}')
        times.append(end_time - start_time)

    avg_time = calculate_average(times)
    print(f'Average time taken {avg_time}')
    return

# Test function for EMM fuzzer


def test_fuzzer(cycles, seed, debug_mode=False):
    start_time = time.time()
    print(f'Fuzzing for {cycles} cycles')

    emm_fuzzer = EMMFuzzer(cycles=cycles, seed=seed, debug_mode=debug_mode)
    i = 0
    target_field_paths = set()
    stats_df = pd.DataFrame(
        columns=['packet_num_mut', 'packet_num_field', 'time', 'cycle', 'total_coverage'])

    while True:
        i += 1
        p, _, _, _ = emm_fuzzer.get_next_packet()
        if p is None:
            print(f'Finished fuzzing after {i} test payloads')
            break

        # Add to coverage map
        # Assuming _ is the path, replace as needed
        target_field_paths.add(tuple(_))
        new_df = pd.DataFrame({
            'packet_num_mut': [i],
            'packet_num_field': [len(target_field_paths)],
            'time': [time.time()],
            'cycle': [emm_fuzzer.get_cycle()],
            'total_coverage': [emm_fuzzer.get_coverage()]
        })
        stats_df = pd.concat([stats_df, new_df])

    end_time = time.time()
    logging.debug(f'Time taken {end_time - start_time}')

    # Save stats to CSV
    stats_df.to_csv('emm_fuzzing_stats.csv', index=False)

# Main function for parsing arguments and running tests



# Main function for parsing arguments and running tests
def main():
    DEFAULT_SEED = 19
    DEFAULT_CYCLES = 1
    DEFAULT_OUTPUT_FILENAME = 'payloads/nas/emm_payloads.txt'

    # Read command line args
    parser = argparse.ArgumentParser(description='Run the NAS EMM fuzzer')
    parser.add_argument(
        '-t', '--test', choices=['gen', 'fuzz'], help='Test NAS EMM Fuzzer')
    parser.add_argument('-c', '--cycles', type=int,
                        help='Number of cycles to run the fuzzer for')
    parser.add_argument('-o', '--output_filename',
                        type=str, help='Output filename')
    parser.add_argument('-s', '--seed', type=int, help='Seed for the fuzzer')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Enable debug mode (enables debug logging)')

    args = parser.parse_args()

    if args.seed is None:
        args.seed = DEFAULT_SEED

    if args.output_filename is None:
        args.output_filename = DEFAULT_OUTPUT_FILENAME

    if args.cycles is None:
        args.cycles = DEFAULT_CYCLES

    # Enable debug logging if debug mode is on
    if args.debug:
        print("Debug mode enabled - debug logging enabled")
        from utils.logging_config import setup_logging
        import logging
        setup_logging(level=logging.DEBUG)


    # Check if the file exists, else create an empty file
    # Create the directory structure if it doesn't exist
    os.makedirs(os.path.dirname(args.output_filename), exist_ok=True)
    
    if not os.path.exists(args.output_filename):
        open(args.output_filename, 'w').close()

    if args.test == 'fuzz':
        test_fuzzer(args.cycles, args.seed, args.debug)
    elif args.test == 'gen':
        test_generator()
    else:
        # Run server if no test specified
        emm_fuzzer = EMMFuzzer(cycles=args.cycles, seed=args.seed, debug_mode=args.debug)
        emm_server = EMMController(
            fuzzer=emm_fuzzer,
            output_file_name=args.output_filename
        )
        emm_server.handle_client()


if __name__ == '__main__':
    main()
