

Message generation RRC : 

Generate a packet with a list of mutations path to fields that can be mutated 

1. For each target field, get the path to the target field and the sequence of choices to reach the target field

2. Iterate over the [(path, choices)] and generate new packets. Do until every target field as been generated.

3. Repeat for different seeds -> different values choosen for packet data.



EMM generation : 

for every EMM msg type 
    enableall optional fields
    recursively_generate_message

    encode and decode to check correctness

Revursively generate message fields such as TAIList, NetworkName, TimeZone, PLMList, EmergNumList by randomly selecting all values and the length of those fields


<!-- 
EMMTypeMTClassesFuzz = {
    66: EMMAttachAccept,
    68: EMMAttachReject,
    69: EMMDetachRequestMT,
    70: EMMDetachAccept,
    73: EMMTrackingAreaUpdateAccept,
    75: EMMTrackingAreaUpdateReject,
    78: EMMServiceReject,
    79: EMMServiceAccept,
    80: EMMGUTIReallocCommand,
    82: EMMAuthenticationRequest,
    84: EMMAuthenticationReject,
    85: EMMIdentityRequest,
    93: EMMSecurityModeCommand,
    96: EMMStatus,
    97: EMMInformation,
    98: EMMDLNASTransport,
    100: EMMCSServiceNotification,
    104: EMMDLGenericNASTransport,
} -->


1 algoroithm for test case generation 

Abstract it as  -> Apply mutation strategies but include special cases



Mutation RRC

BASE = mutate length and content of buffers  (L | Data), integers bounds if from 0 to 9 we also use 10 to 16 due to bits

- SEQOF -> mutate the length field between 0 and the max length that can be represented on the length bits
        * set length to 0 while having content
        * set randomly between 0 and max length while keeping fixed content
        * set length to max lenght while keeping content
- INTEGERS -> use the full bit range, not the spec constraintsW
- BITSTRING -> same as octet string bit Bit instead of Bytes.
- OCTETSTRING -> depending on if the field is constraint or not the mutation are different
        - Unconstrained -> cite the specs, depending on the total length there are multiple chunks, also mutate length
            - for specific length values that impact the structure of the unconstrained field we generate 
                - an invalid length encoding
                - empty content
                - length set to content length - 1  
        - Constrained -> there is a max number of bits for the length, same mutation as seqof length :
            - length set to valid length, empty content
            - length 0 content to fix length non empty
            - length set to content length - 1
            - length set to max possible length that can be encoded, content to max size for this field
            -



TRUNCATE = truncate packet 
ADD = add randomly optional fields (selection of random optional fields)


Mutation NAS

BASE : mutate TLV field lenghts of buffers and the lengths of buffers in fields,  handle in a special case the IEs with internal structure
TAG : mutate field TAG and EMMHeader
ADD : add random optional fields
APPEND : append random bytes at the end
FLIP : flip bits
TRUNCATE : truncate packet




dis 5760

total 24078





Seed 1  
BASE ADD
OCT BIT SEQ OF Number of test payloads 24466



Seed 1  
BASE TRUNCATE
OCT BIT SEQ OF Number of test payloads 28790

Seed 1  
BASE TRUNCATE
OCT INT SEQ OF Number of test payloads 41198

Seed 1  
BASE TRUNCATE ADD
OCT BIT SEQ OF Number of test payloads 28790


Seed 1  
BASE TRUNCATE ADD
OCT BIT INTEGER Number of test payloads 34060



Files 

1: Seed 1 OBI BT
2
3: 
4
5: Seed 3 OBI BTA