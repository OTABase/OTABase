import matplotlib.pyplot as plt

from rrc_stats import get_stats_mutation_paths, get_target_field_count
from rrc_fields import Fields
from rrc_generator import RRCGenerator
import logging
import time



def test_generation(targets, num=1000, plot=False):
    MONITOR_SET = set()
    lengths = []
    ratios = []
    last_added = None
    goal = get_target_field_count(targets=targets)
    seed = 19
    rrc_generator = RRCGenerator(targets=targets, seed=seed)
    for i in range(num):
        if i % 100 == 0:  # Show progress every 100 iterations
            logging.info(f'Iteration {i}, coverage : {len(MONITOR_SET)} / {goal}')
        else:
            logging.debug(f'Iteration {i}, coverage : {len(MONITOR_SET)} / {goal}')
        _, _, mutation_paths, _ = rrc_generator.generate_packet()
        tot_length = len(mutation_paths)
        count = 0
        for m in mutation_paths:

            # Removing different SEQOF content mutations
            new_m = [x for x in m if not isinstance(x, int)]

            if tuple(new_m) not in MONITOR_SET:
                count += 1
                MONITOR_SET.add(tuple(new_m))
                last_added = new_m
                ratios.append(f'{count} / {tot_length}')
        lengths.append(len(MONITOR_SET))

        if lengths[-1] == goal:
            logging.info('All paths covered')
            break

    if plot:
        # Plot the lengths according to the number of generated packets
        plt.plot(lengths)
        plt.ylabel('Number of unique paths')
        plt.xlabel('Number of generated packets')
        plt.show()

    return MONITOR_SET, lengths, ratios, last_added


def plot_average_coverage(iterations, targets):
    all_lengths = []
    all_last_added = []
    all_times = []
    for i in range(iterations):
        start = time.time()
        _, lengths, _, last_added = test_generation(
            targets, num=12500, plot=False)
        end = time.time()
        all_lengths.append(lengths)
        all_last_added.append(last_added)
        logging.info(f'Execution time: {end - start} seconds')
        time_spent = end - start
        all_times.append(time_spent)

    avg_time = sum(all_times) / len(all_times)
    logging.info(f'Average time: {avg_time} seconds')

    # Average the length of all list in all_lengths
    avg_iterations = [len(x) for x in all_lengths]
    avg_iterations = sum(avg_iterations) / len(avg_iterations)
    logging.info(f'Average iterations: {avg_iterations}')

    # Compute average lengths
    avg_lengths = []
    for l in zip(*all_lengths):
        avg_lengths.append(sum(l) / len(l))

    # Compute standard deviation at each index
    std_lengths = []
    for l in zip(*all_lengths):
        mean = sum(l) / len(l)
        std = (sum((x - mean) ** 2 for x in l) / len(l)) ** 0.5
        std_lengths.append(std)

    plt.plot(range(1, len(avg_lengths) + 1), avg_lengths)
    plt.fill_between(range(1, len(avg_lengths) + 1), [x - y for x, y in zip(avg_lengths, std_lengths)],
                     [x + y for x, y in zip(avg_lengths, std_lengths)], alpha=0.2)
    plt.ylabel('Number of unique paths')
    plt.xlabel('Generated packets')
    plt.show()


if __name__ == '__main__':
    targets = [Fields.BIT_STRING, Fields.OCTET_STRING]

    plot_average_coverage(10, targets)

    exit(0)
    gen_paths, _, _, _ = test_generation(targets=targets, num=1000, plot=False)
    stats_paths = get_stats_mutation_paths(targets=targets, optional=True)

    # Format paths obtained from stats
    new_stats_paths = []
    for p in stats_paths:
        new_stats_paths.append(tuple([x for x in p if x[0] != '_']))

    # Format paths obtained from generation
    new_gen_paths = []
    for p in gen_paths:
        skip_next = False
        l = []
        for x in list(p):
            if x == '*':
                skip_next = True
                continue

            if not skip_next:
                l.append(x)
            else:
                skip_next = False

        new_gen_paths.append(tuple(l))

    logging.info('---------------------------')
    diff = set(new_stats_paths) - set(new_gen_paths)

    if len(diff) > 0:
        logging.info('Difference found in stats paths')
        logging.info(diff)

    diff = set(new_gen_paths) - set(new_stats_paths)

    if len(diff) > 0:
        logging.info('Difference found in generated paths')
        logging.info(diff)
