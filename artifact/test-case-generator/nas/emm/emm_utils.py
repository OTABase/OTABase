from pycrate_mobile.NAS import *
from pycrate_mobile import *
from pycrate_core import *
from pycrate_csn1.csnobj import *

import random 

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
}


def flip_bits(data, flip_probability=0.02):
    """
    Randomly flips bits in the input data with a given probability.

    Parameters:
        data (bytes): Input data to flip bits in.
        flip_probability (float): Probability of flipping a bit, should be in the range [0, 1].

    Returns:
        bytes: Flipped data.
    """
    flipped_data = bytearray()
    for byte in data:
        flipped_byte = 0
        for i in range(8):
            if random.random() < flip_probability:
                flipped_byte |= 1 << i
            else:
                flipped_byte |= (byte & (1 << i))
        flipped_data.append(flipped_byte)
    return bytes(flipped_data)