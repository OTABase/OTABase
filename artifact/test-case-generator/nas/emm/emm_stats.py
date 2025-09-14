from pycrate_mobile.NAS import *
from pycrate_mobile import *
from pycrate_core import *
from pycrate_csn1.csnobj import *


from nas.nas_utils import enable_all_optional_fields
from nas.emm.emm_utils import EMMTypeMTClassesFuzz

# All downlink messages

def get_emm_target_field_count() -> int:
    """
    Computes the number of target fields in all of the EMM downlink messages.

    Returns:
        int: number of fields in the target message.
    """

    target_field_count = 0
    coverage = set()
    for msg_type in EMMTypeMTClassesFuzz.values():
        
        msg = msg_type()
        enable_all_optional_fields(msg)

        for m in msg[1:]:

            # if type(m) in (Type1TV, Type3TV, Type4TLV, Type4LV, Type6TLVE, Type6LVE):
            target_field_count += 1
            coverage.add((msg._name, m._name))

        # Add EMMHeader
        target_field_count += 1
        coverage.add((msg._name, 'EMMHeader'))
    return target_field_count
