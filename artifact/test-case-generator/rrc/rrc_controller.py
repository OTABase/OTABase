from rrc.rrc_fuzzer import RRCFuzzer
from enum import Enum
from utils.logging_config import setup_logging

import logging
import os

# Ensure logging is configured
setup_logging()

class RRCController:

    def __init__(self,
                 fuzzer: RRCFuzzer,
                 output_file_name='rrcTest0'):

        self.fuzzer = fuzzer
        # Start search earéy for faster generation
        self.fuzzer.start_search()

        # output_name
        self.output_file_name = output_file_name

    def update_payload_file(self, payload, target_msg, target_field):
        """ Writes a payload to the payload file

        Args:   
            payload (bytes): The payload to write to the file
            target_msg (str): The target message
            target_field (str): The target field

        Returns:
            None
        """
        try:
            # Find the next available filename
            filename = self.output_file_name
            currentLineNumber, totalPayloads = 1, 0
            logging.debug(f"Updating the file {filename}")
            file_exists = os.path.exists(filename)
            if not file_exists:
                logging.debug(f'File does not exist')
                with open(filename, 'w') as file:
                    file.write(f"{totalPayloads}\n")
                file.close()
            with open(filename, 'r+') as file:
                # If the file exists, read the first line to get the currentLineNumber and totalPayloads
                if file_exists:
                    file.seek(0)
                    first_line = file.readline()
                    if first_line:
                        totalPayloads = int(first_line)
                        logging.debug(f'Total payloads :{totalPayloads}')
                    if totalPayloads == 0:
                        logging.debug(f'File exists but no payloads in it')
                    # # Rewind to the beginning of the file
                    # file.seek(0)
                else:
                    logging.debug(f'File does not exist???')
                    currentLineNumber, totalPayloads = 1, 0
                    file.write(f"{totalPayloads}\n")

                # Increment the number of payloads
                totalPayloads += 1
                # Remove the 'b' and signal quotEs from the payload
                payload_string = payload.decode('utf-8')
                # payload_string = payload_string[2:-1]
                cur_pos = file.tell()
                file.seek(0)
                totalPayloads_width = 6
                formatted_totalPayloads = str(
                    totalPayloads).zfill(totalPayloads_width)
                file.write(f"{formatted_totalPayloads}\n")
                # Progress milestone logging
                coverage = self.fuzzer.get_coverage()
                if totalPayloads % 500 == 0:
                    logging.info(f'Progress: {totalPayloads} payloads, coverage: {coverage:.3f} ({coverage*100:.1f}%)')
                elif totalPayloads % 100 == 0:
                    logging.info(f'Payloads: {totalPayloads}, coverage: {coverage:.3f}')
                else:
                    logging.debug(f'Payload {totalPayloads}, coverage: {coverage:.4f}')
                # Append the payload in the desired format
                payload_line = f"{totalPayloads},{
                    payload_string},{target_msg},{target_field}\n"
                logging.debug(f"Coverage: {self.fuzzer.get_coverage():.4f}")

                file.seek(0, os.SEEK_END)

                file.write(payload_line)
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")

    def generate_payload_file(self):
        """Handle a client connection

        Args:
            client_socket (socket): The client socket
            address (str): The client address
            num_connections (ints): The number of connections
        """

        while True:

            rrc_packet = b''
            rrc_packet, path, strategy = self.fuzzer.get_next_packet()
            if rrc_packet == None:
                # logging.info('RRC packet is None, exiting')
                break

            rrc_packet = (rrc_packet.hex()).encode()
            self.update_payload_file(rrc_packet, path[2], ",".join(path))

    def start_server(self):
        logging.info('Starting RRC payload generation')
        self.generate_payload_file()