# OTABase - Over-the-Air LTE Baseband Testing Framework

OTABase is a comprehensive over-the-air LTE baseband testing framework specifically designed to detect memory crashes in cellular baseband processors. To overcome the limitations of black-box over-the-air testing for memory bug detection, our framework combines three key techniques:

1. **Network-side state control mechamism** — protocol-guided state transitions with automatic reconnection, avoiding long back-off timers and ensuring sustained testing.
2. **Specification-guided test case generation** — standard-conformant message generation with targeted mutations of security-sensitive fields, expanding coverage while maintaining validity.
3. **Crash detection oracle** — protocol-level liveness checks combined with vendor-specific debug features for identifying memory crashes in a black-box environment.

OTABase targets **RRC (Radio Resource Control)** and **NAS (Non-Access Stratum)** protocols to uncover memory vulnerabilities in commercial baseband processors. It has successfully uncovered **seven new vulnerabilities** across **six commercial baseband processors** from **three major manufacturers**. Please refer to our paper for the details. 

## Dependencies
- Ubuntu machine (18.04/22.04 LTS)
- USRP B210 (or equivalent SDR) and antennas
- Programmable test SIM card (e.g. [SysmoISIM-SJA2](https://sysmocom.de/products/sim/sysmousim/index.html))
- Test smartphones
- Faraday cage

## Artifact Structure

It combines two major components:

1. **OTABase Execution Framework** (`artifact/otabase/`)  
- Extends [srsRAN](https://github.com/srsran/srsRAN_4G) to send generated test cases over-the-air to the testing UE.  
- Includes network-side state management, test message transmission/response handling, and crash detection.

2. **Test Case Generator** (`artifact/test-case-generator/`)  
- Generates RRC and NAS test cases by creating standard-conformant base messages and mutating target fields.
- Implemented in Python with [pycrate](https://github.com/P1sec/pycrate).


## Usage Overview

To run OTABase end-to-end, follow these steps:

1. **Setup dependencies**  
- Prepare system requirements (Ubuntu 18.04/22.04 LTS, Python 3.8+, USRP B210, programmable SIM, test smartphone, Faraday cage).  
- Install dependencies for running [srsRAN_4G](https://github.com/srsran/srsRAN_4G), which is extended by the OTABase.  
- Install Python dependencies for the Test Case Generator (`pycrate`, `pandas`).  
Detailed setup instructions can be found in the [Installation](#installation) section. 

2. **Generate test cases** using the Specification-guided Test Case Generator.  
- This will produce files containing payloads of the test messages (e.g., `payloads/rrc/rrc_payloads.txt`, `payloads/nas/emm_payloads.txt`) containing mutated RRC/NAS messages.   
- See [Specification-guided Test Case Generation](#specification-guided-test-case-generation) for detailed instructions.  


3. **Execute test cases over-the-air** using the OTABase Execution Framework.  
The framework extends [srsRAN](https://github.com/srsran/srsRAN_4G) to transmit the generated payloads to the target UE, manage network-side state, and monitor for crashes.  
See [OTABase Execution Framework](#otabase-execution-framework) for detailed setup and usage.


## OTABase

## Table of Contents

- [Installation](#installation)
- [OTABase over-the-air execution](#specification-guided-test-case-generation)
  - [Execution](#execution)
  - [Option reference](#option-reference)
  - [testFileIndex behavior](#testfileindex-behavior)
- [Specification-guided Test Case Generation](#specification-guided-test-case-generation)
  - [Usage](#usage)
    - [RRC Fuzzing](#rrc-fuzzing)
    - [NAS EMM Fuzzing](#nas-emm-fuzzing)
  - [Field Types](#field-types)
  - [Debug Mode](#debug-mode)
  - [Packet Generation](#packet-generation)
    - [RRC Packet Generation](#rrc-packet-generation)
    - [NAS EMM Packet Generation](#nas-emm-packet-generation)
  - [Mutation Strategies](#mutation-strategies)
    - [RRC Strategies](#rrc-strategies)
    - [NAS Strategies](#nas-strategies)
  - [Output Format](#output-format)




## Installation

### Prerequisites
- Python 3.8+
- Git
- UHD driver 3.9.7 or 3.15 (See [link](https://github.com/EttusResearch/uhd))
- Android Debug Bridge (adb)

### Quick Start

After satisfiying the [dependencies](#dependencies), you need to install `artifact/otabase` and `artifact/test-case-generator`. 

```bash
# OTABase over-the-air framework
git clone <repository-url>
cd artifact/otabase
chmod +x install.sh
./install.sh
```


OTABase's test case generator (`artifact/test-case-generator/`) features automatic setup - just clone and run:

```bash
# OTABase test case generator
cd artifact/test-case-generator
chmod +x run.sh
./run.sh 
```

On first run, this will automatically:
- Create a Python virtual environment (`otabase_venv`)
- Install all required dependencies
- Run both RRC and NAS fuzzers

### Manual Setup

#### Dependencies

If you prefer manual installation, you need to install the following packages. 

Python: 
- `pycrate` - Runtime for encoding/decoding CSN.1 and ASN.1 data structures for cellular signalling
- `pandas` - Data analysis and statistics


Ubuntu: 
```bash 
sudo apt-get install build-essential cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev
```

Then,

```bash
# 1. Clone the repository
git clone <repository-url>

# 2. Install otabase (modified version of srsRAN)
cd artifact/otabase
mkdir build
cd build
cmake ..
make -j$(nproc)

# 3. Install otabase's test case generator (python, virtual environment)
cd artifact/test-case-generator
python3 -m venv otabase_venv
source otabase_venv/bin/activate  # On Windows: otabase_venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt
```




## OTABase over-the-air execution

First, follow the [Specification-guided Test Case Generation](#specification-guided-test-case-generation) to generate the NAS/RRC test cases. 
You can also use the example test cases provided in `artifact/otabase/example-test-case`.
- If you want to run multiple test case files, set test file's name like name1, name2, name3, ... (e.g. nasTest1, nasTest2, ...)

## Execution with example
NAS testing

```bash
(Terminal 1)
cd ($OTABase)/build/srsepc/src

cp ../../../example-test-case/nas/* .
# If the test case file's name is nasTest1, echo "nasTest1" > testFileIndex
echo ($testfilename) > testFileIndex
# execute the framework 
sudo ./srsepc ../../../conf/epc/epc.conf —enable_reattach=1 —mme.ota_timer=10 —test_state=pre-aka —o=($outdir)

```
```bash
(Terminal 2)
cd ($OTABase)/build/srsenb/src
# execute the framework 
sudo ./srsenb ../../../conf/enb/enb.conf —target_protocol=nas —o=($outdir) —rf.dl_earfcn=3050
```

RRC testing

```bash
(Terminal 1)
cd ($OTABase)/build/srsepc/src
# execute the framework 
sudo ./srsepc ../../../conf/epc/epc.conf —enable_reattach=1 —mme.ota_timer=10 —test_state=pre-aka —o=($outdir)

```
```bash
(Terminal 2)
cd ($OTABase)/build/srsenb/src
cp ../../../example-test-case/rrc/* .
# If the test case file's name is rrcTest1, echo "rrcTest1" > testFileIndex
echo ($testfilename) > testFileIndex
# execute the framework 
sudo ./srsenb ../../../conf/enb/enb.conf —target_protocol=rrc —o=($outdir) —rf.dl_earfcn=3050
```

### Option reference

---

- `--target_protocol={nas|rrc}`  
  Selects the protocol under test. Use `nas` for NAS test cases and `rrc` for RRC test cases.

- `--rf.dl_earfcn=<EARFCN>`  
  Sets the downlink EARFCN (operating frequency). Choose a value that matches your RF plan and hardware/regulatory constraints.

- `--test_state={pre-aka|post-aka|tau|sr}`  
  Controls the initial network-side state for testing:  
  - `pre-aka` → **REGI-Init** state  
  - `post-aka` → **REGI** state  
  - `tau` → **TAU-Init** state  
  - `sr` → **SR-Init** state

- `--o=<path>`  
  Output directory where bug candidates and runtime artifacts are collected.

- `--mme.ota_timer=<seconds>`  
  Re-attach interval (in seconds). Sets the timer the framework uses to periodically re-attach the UE for sustained OTA testing.

- `--enable_reattach={0|1}`  
  Enables automatic re-attach via state control. When `1`, the framework recovers from attach failures/back-off without manual intervention.

---

### `testFileIndex` behavior

- `testFileIndex` indicates the current test file name (e.g., `nasTest1`, `rrcTest7`) and is updated by the framework as execution proceeds.  
- When sending one test case at a time, the framework records progress (e.g., which file and which line/offset was last transmitted).  
- If the framework stops mid-run, restarting will resume from the recorded position in `testFileIndex`, continuing with the next unsent line or the next file as needed.  
- You can manually prime the run by writing an initial file name:
  ```bash
  echo "nasTest1" > testFileIndex
  # or
  echo "rrcTest1" > testFileIndex
  ```



## Specification-guided Test Case Generation

## Usage

### RRC Fuzzing

The RRC fuzzer targets Radio Resource Control protocol messages with configurable field types and strategies.

#### Basic Usage

```bash
# Run with default settings (targets OCTET_STRING fields)
python main_rrc.py

# Specify output file and seed
python main_rrc.py -o my_rrc_payloads.txt -s 42
```

#### Field Targeting

```bash
# Target specific field types
python main_rrc.py -f INTEGER                    # Only integers
python main_rrc.py -f OCTET_STRING BIT_STRING    # Multiple types
python main_rrc.py -f BIT_STRING OCTET_STRING INTEGER SEQOF  # All types
```

#### Advanced Options

```bash
# Complete configuration
python main_rrc.py \
  -f OCTET_STRING INTEGER \
  -c 5 \
  -s 123 \
  -o payloads/rrc/custom_test.txt

# Run benchmarks
python main_rrc.py -t benchmark

# Test generation only
python main_rrc.py -t gen

# Run fuzzer test mode
python main_rrc.py -t fuzz -c 3 -s 456
```

#### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--fields` | `-f` | Target field types (BIT_STRING, OCTET_STRING, INTEGER, SEQOF) | OCTET_STRING |
| `--cycles` | `-c` | Number of fuzzing cycles | 1 |
| `--seed` | `-s` | Random seed for reproducibility | 1 |
| `--output_filename` | `-o` | Output payload file path | `payloads/rrc/rrc_payloads.txt` |
| `--debug` | `-d` | Enable debug mode (saves coverage files and enables debug logging) | False |
| `--test` | `-t` | Test mode (gen, fuzz, benchmark, find) | None (normal mode) |

### NAS EMM Fuzzing

The NAS EMM fuzzer targets EPS Mobility Management protocol messages.

#### Basic Usage

```bash
# Run with default settings
python main_emm.py

# Specify output file and seed
python main_emm.py -o my_nas_payloads.txt -s 42
```

#### Advanced Options

```bash
# Complete configuration
python main_emm.py \
  -c 3 \
  -s 789 \
  -o payloads/nas/custom_emm_test.txt

# Test generation only
python main_emm.py -t gen

# Run fuzzer test mode
python main_emm.py -t fuzz -c 2 -s 101
```

#### Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--cycles` | `-c` | Number of fuzzing cycles | 1 |
| `--seed` | `-s` | Random seed for reproducibility | 19 |
| `--output_filename` | `-o` | Output payload file path | `payloads/nas/emm_payloads.txt` |
| `--debug` | `-d` | Enable debug mode (enables debug logging) | False |
| `--test` | `-t` | Test mode (gen, fuzz) | None (normal mode) |

## Field Types

### RRC Field Types
The RRC fuzzer can target the following security-sensitive field types:

- **`BIT_STRING`**: Variable-length bit sequences
- **`OCTET_STRING`**: Byte sequences and binary data  
- **`INTEGER`**: Numeric values with various constraints
- **`SEQOF`**: Sequence of repeated elements

### NAS Field Types
The NAS EMM fuzzer automatically identifies and targets appropriate fields within EMM messages based on the protocol specification.

## Debug Mode

Both RRC and NAS fuzzers support debug mode, which can be enabled using the `-d` or `--debug` flag:

### Debug Mode Features:
- **Enhanced Logging**: Enables debug-level logging to show detailed fuzzing operations
- **RRC Coverage Files**: For RRC fuzzing, saves grammar coverage files to the `rrc_coverage/` folder including:
  - `rrc_coverage/grammar_coverage_add.csv`: Coverage statistics over time
  - `rrc_coverage/full_grammar_coverage_set.json`: Complete set of covered grammar elements
  - `rrc_coverage/full_IE_name_coverage_set.json`: Information Element name coverage
  - `rrc_coverage/rrc_full_grammar_coverage_set.json`: Runtime grammar coverage tracking

Note that coverage files for NAS-EMM are not needed as the fuzzer coveres all possible fields in each cycle.

### Usage:
```bash
# Enable debug mode for RRC fuzzing
python main_rrc.py -d -f OCTET_STRING -o debug_test.txt

# Enable debug mode for NAS EMM fuzzing  
python main_emm.py -d -c 2 -o debug_nas.txt
```

**Note**: Debug mode produces more verbose output and additional files. Use only when detailed analysis is needed.

## Packet Generation

This section describes how the fuzzers generate base packets before applying mutations.

### RRC Packet Generation

The RRC fuzzer employs a sophisticated ASN.1-aware generation strategy to create valid base packets:

#### **Choice Path Strategy**
1. **Pre-analysis Phase**: Analyze the ASN.1 grammar to identify all possible paths to target field types
2. **Choice Sequence Mapping**: For each target field, map the sequence of CHOICE decisions needed to reach it
3. **Path Prioritization**: Use a round-robin approach through choice paths, avoiding already-explored combinations

#### **Recursive ASN.1 Traversal**
The generator recursively traverses the ASN.1 structure with type-specific handling:

- **SEQUENCE**: Process all mandatory fields, optionally include optional fields
- **CHOICE**: Follow predetermined choice paths to reach target fields, fall back to random selection
- **INTEGER**: Generate values within specification constraints (bounds checking for mutation potential)
- **OCTET STRING**: Handle both constrained and unconstrained lengths, support embedded content
- **BIT STRING**: Generate appropriate bit sequences with length constraints
- **SEQUENCE OF**: Create variable-length sequences with configurable element counts

#### **Embedded Content Handling**
- **Recursive Expansion**: Automatically decode and expand embedded ASN.1 content within OCTET STRINGs
- **Depth Control**: Limit recursive expansion to prevent infinite loops
- **Path Tracking**: Maintain full path information including embedded boundaries (marked with '*')

#### **Target-Guided Generation**
- **Field Targeting**: Only generate mutation paths for fields matching the target types
- **Coverage Optimization**: Track already-covered paths to avoid redundant generation
- **Smart Selection**: Prioritize paths that lead to unexplored target fields

#### **Optional Field Strategy**
- **Configurable Inclusion**: Enable/disable optional fields based on coverage requirements
- **Path Collection**: Separately track optional paths for potential mutation strategies
- **Minimal Generation**: Generate smallest valid packets while ensuring target field reachability

The generation process ensures comprehensive coverage of all reachable target field types while maintaining ASN.1 validity and supporting complex nested structures typical in RRC protocols.

### NAS EMM Packet Generation

The NAS EMM fuzzer uses a comprehensive approach to cover all EMM message types:

1. **Message Type Iteration**: For every EMM message type in the protocol specification, generate base packets.

2. **Optional Field Enablement**: Enable all optional fields to maximize the attack surface and ensure comprehensive coverage.

3. **Recursive Field Generation**: Recursively generate complex message fields such as:
   - TAI Lists (Tracking Area Identity Lists)
   - Network Names
   - Time Zones  
   - PLM Lists (Public Land Mobile Network Lists)
   - Emergency Number Lists
   
   These fields are generated by randomly selecting values and appropriate lengths.

4. **Validation**: Encode and decode each generated packet to verify correctness before proceeding to mutation.

The EMM generation process ensures complete coverage of all possible EMM message types and their optional components.

## Mutation Strategies

This section details the mutation approaches used to generate malformed packets from the base packets.

### Abstract Mutation Framework

Both RRC and NAS fuzzers apply mutation strategies that include special cases for different field types. The general approach is:

**Apply targeted mutation strategies while handling protocol-specific special cases**

### RRC Strategies

The RRC fuzzer implements several mutation strategies targeting different field types:

#### **BASE Strategy**
Mutates the length and content of buffers `(Length | Data)` and exploits integer bounds. For integers constrained from 0-9, the fuzzer also tests values 10-16 due to available bit representation.

**Field-Specific Mutations:**

- **SEQUENCE OF Fields**:
  - Mutate the length field between 0 and the maximum length representable by the length bits
  - Set length to 0 while having content present
  - Set length randomly between 0 and max length while keeping fixed content  
  - Set length to maximum possible value while keeping content

- **INTEGER Fields**:
  - Use the full bit range available, not just the specification constraints
  - Test boundary values and overflow conditions

- **BIT STRING Fields**:
  - Same approach as OCTET STRING but operates on bits instead of bytes
  - Length and content manipulation at bit level

- **OCTET STRING Fields**:
  Mutations depend on whether the field is constrained or unconstrained:
  
  **Unconstrained OCTET STRING**:
  - Multiple encoding chunks based on total length (per ASN.1 PER encoding rules)
  - Generate invalid length encodings
  - Empty content with various length values
  - Set length to `content_length - 1` (underflow condition)
  
  **Constrained OCTET STRING**:
  - Limited bits available for length encoding (similar to SEQUENCE OF)
  - Length set to valid value with empty content
  - Length set to 0 with non-empty content
  - Length set to `content_length - 1` 
  - Length set to maximum encodable value with maximum content size

#### **TRUNCATE Strategy**
Truncates packets at random positions to test parser robustness against incomplete data.

#### **ADD Strategy**  
Randomly adds optional fields to packets to increase complexity and test edge cases in parsers that handle varying packet structures.

### NAS Strategies

The NAS EMM fuzzer implements comprehensive mutation strategies targeting the TLV (Type-Length-Value) structure of NAS messages:

#### **BASE Strategy**
Mutates TLV field lengths and buffer lengths within fields. Special handling is provided for Information Elements (IEs) with internal structure.

#### **TAG Strategy**  
Mutates field TAG values and EMM header components to test protocol parsing robustness against invalid or unexpected message types.

#### **ADD Strategy**
Adds random optional fields to EMM messages to test parsers against unexpected message compositions and field combinations.

#### **APPEND Strategy**
Appends random bytes at the end of packets to test buffer overflow protection and packet boundary validation.

#### **FLIP Strategy**
Performs bit-flipping operations on packet data to simulate transmission errors and test error handling mechanisms.

#### **TRUNCATE Strategy**
Truncates packets at various positions to test parser robustness against incomplete or malformed messages.

The NAS EMM fuzzer provides comprehensive coverage by targeting both the structural elements (TLV encoding) and content-specific vulnerabilities in EMM protocol implementations.

## Output Format

Both fuzzers generate structured payload files with the following format:

```
<total_payload_count>
<payload_id>,<hex_payload>,<target_message_type>,<target_field_path>
<payload_id>,<hex_payload>,<target_message_type>,<target_field_path>
...
