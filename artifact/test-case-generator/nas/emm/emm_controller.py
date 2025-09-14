from enum import Enum
from abstract_classes.fuzzer import Fuzzer
from nas.emm.emm_fuzzer import EMMFuzzer
from nas.emm.emm_strategy import EMMStrategy


import logging
import os

import pandas as pd
from utils.logging_config import setup_logging

# Logging is automatically configured when utils.logging_config is imported


class EMMOracleType(Enum):
    ADB = 0
    TIMEOUT_ACK = 1
    IDF = 2


class EMMController:

    def __init__(self,
                 fuzzer: Fuzzer,
                 output_file_name='nasTest0'):

        self.fuzzer = fuzzer
        self.output_file_name = output_file_name

    def handle_client(self):
        """
        Handles the connection of a client

        Args:
            client_socket (socket): socket to communicate with the client
            address (tuple): address of the client
        """

        logging.info('Starting NAS EMM payload generation')
        while True:

            packet, packet_type, target_field, strategy = self.fuzzer.get_next_packet()

            logging.debug("Got new packet from fuzzer")
            if packet is None:
                logging.info('EMM fuzzing completed - all packets generated')
                break
            # Check length in bytes
            if len(packet) < 2037:
                logging.debug(f'Packet length is {len(packet)}')
                logging.debug(packet)
                packet = packet.hex().encode()
                logging.debug(f'Packet to be sent {packet}')
                self.update_payload_file(packet, packet_type, target_field)

            else:
                logging.debug(
                    f'Ignoring mutation of length {len(packet)}')

        return

    def update_payload_file(self, payload, target_msg, target_field):
        try:
            # Find the next available filename
            filename = self.output_file_name
            currentLineNumber, totalPayloads = 1, 0
            logging.debug(f"Updating the file")
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
                    first_line = file.readline().strip()
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

                totalPayloads += 1
                # Remove the 'b' and signal quotEs from the payload
                payload_string = payload.decode('utf-8')
                # payload_string = payload_string[2:-1]
                file.seek(0)
                totalPayloads_width = 6
                formatted_totalPayloads = str(
                    totalPayloads).zfill(totalPayloads_width)
                file.write(f"{formatted_totalPayloads}\n")
                
                # Progress milestone logging
                if totalPayloads % 1000 == 0:
                    logging.info(f'EMM Progress: {totalPayloads} payloads generated')
                elif totalPayloads % 250 == 0:
                    logging.info(f'EMM Payloads: {totalPayloads}')
                else:
                    logging.debug(f'EMM Payload {totalPayloads}')
                
                # Append the payload in the desired format
                payload_line = f"{totalPayloads},{
                    payload_string},{target_msg},{target_field}\n"

                file.seek(0, os.SEEK_END)
                logging.debug(f"Writing payload line {payload_line}")
                file.write(payload_line)
        except Exception as e:
            logging.error(f"EMM payload file update error: {str(e)}")
