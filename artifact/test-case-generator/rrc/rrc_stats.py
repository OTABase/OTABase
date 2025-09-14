from rrc.releaseLTE_R17 import RRCLTE_R17

from pycrate_asn1rt import *
from pycrate_asn1rt.utils import *
from pycrate_asn1rt.err import *
from pycrate_asn1rt.refobj import *
from pycrate_asn1rt.dictobj import *
from pycrate_asn1rt.setobj import *
from pycrate_asn1rt.codecs import *

from rrc.rrc_fields import Fields

import os
import json
import csv

def add_dicts(dict1, dict2):
    result = {}
    for key in set(dict1.keys()) | set(dict2.keys()):
        if key in dict1 and key in dict2:
            if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
                result[key] = add_dicts(dict1[key], dict2[key])
            else:
                result[key] = dict1[key] + dict2[key]
        elif key in dict1:
            result[key] = dict1[key]
        else:
            result[key] = dict2[key]
    return result


def get_stats(sel, w_open=True, w_opt=True, targets=[], curr_path=[]):
    """
    Modified get_complexity function from pycrate_asn1rt.

    Returns the number of basic types objects referenced from self,
    the maximum depth possible within self,
    and the list of paths that lead to recursion.

    Args:
        w_open      : bool,
                    if True, inspects the potential content of OPEN objects.
        w_opt       : bool,
                    if True, inspect optional components to count into the complexity.
        targets     : list,
                    list of the paths to target fields.
        curr_path   : list,
                    current path in the ASN.1 specification tree.

    Returns:
        recur       : list,
                    list of paths that lead to recursion.
        stats       : dict,
                    dictionary of the number of bound and unbound fields
                    for each target field.
        mutation_paths : list,
                    list of paths to fields that can be mutated.
        
        ies : set, set containing all the IE names to compute grammar coverage
    """

    stats = {}

    ies = set()

    for t in targets:
        stats[t] = {'bound': 0, 'unbound': 0}

    recur, mutation_paths = [], []
    #
    if not hasattr(sel, '_proto_recur'):
        root = True
        sel._proto_recur = [id(sel)]
        sel._proto_path = []
    else:
        root = False

    

    if sel.TYPE in (TYPE_CHOICE, TYPE_SEQ, TYPE_SET, TYPE_CLASS):
       
        for (ident, Comp) in sel._cont.items():
            if id(Comp) in sel._proto_recur:
                recur_path = sel._proto_path
                # recur_path = sel._proto_path + [ident]
                recur.append(recur_path)

            elif w_opt or not hasattr(sel, '_root_mand') \
                    or Comp._name in sel._root_mand:
                        
                path = curr_path
                next_path = path + [ident]
                 
                Comp._proto_recur = sel._proto_recur + [id(Comp)]
                Comp._proto_path = sel._proto_path + [ident]
                comp_recur, comp_stats, comp_mut, comp_ies = get_stats(
                    Comp,
                    w_open,
                    w_opt,
                    targets,
                    next_path)
                del Comp._proto_recur, Comp._proto_path
                stats = add_dicts(stats, comp_stats)
                recur.extend(comp_recur)
                mutation_paths += comp_mut
                ies = ies.union(comp_ies)        
            
    # SEQUENCE OF and SET OF
    elif sel.TYPE in (TYPE_SEQ_OF, TYPE_SET_OF):
        Comp = sel._cont
    
        if id(Comp) in sel._proto_recur:
            recur_path = sel._proto_path + [None]
            recur.append(recur_path)
        else:      
            next_path = curr_path + [Comp._name]
      
            if Comp._name == '_item_' and sel._tr is not None:
                next_path = curr_path + ['^', sel._tr._name]
          

            Comp._proto_recur = sel._proto_recur + [id(Comp)]
            Comp._proto_path = sel._proto_path + [None]
            comp_recur, comp_stats, comp_mut, comp_ies = get_stats(
                Comp,
                w_open,
                w_opt,
                targets,
                next_path)
            del Comp._proto_recur, Comp._proto_path

            stats = add_dicts(stats, comp_stats)
            recur.extend(comp_recur)
            mutation_paths += comp_mut
            ies = ies.union(comp_ies)
            
        if sel.TYPE in (TYPE_SEQ_OF) and Fields.SEQOF in targets and \
            sel._const_sz.lb != sel._const_sz.ub:
            
            mutation_paths.append(curr_path)
            stats[Fields.SEQOF]['bound'] += 1

    # OCTET STRING and BIT STRING with continuation
    elif sel.TYPE in (TYPE_BIT_STR, TYPE_OCT_STR) and sel._const_cont:
        Comp = sel._const_cont
        if id(Comp) in sel._proto_recur:
            recur_path = sel._proto_path + [None]
            recur.append(recur_path)

        else:
            Comp._proto_recur = sel._proto_recur + [id(Comp)]
            Comp._proto_path = sel._proto_path + [None]
            comp_recur, comp_stats, comp_mut, comp_ies = get_stats(
                Comp,
                w_open,
                w_opt,
                targets,
                curr_path + [Comp._name])
            del Comp._proto_recur, Comp._proto_path
            stats = add_dicts(stats, comp_stats)
            recur.extend(comp_recur)
            mutation_paths += comp_mut
            ies = ies.union(comp_ies)

        if sel.TYPE is TYPE_OCT_STR and Fields.OCTET_STRING in targets:
            if sel._const_sz != None and sel._const_sz.lb != sel._const_sz.ub:
                mutation_paths.append(curr_path)
                stats[Fields.OCTET_STRING]['bound'] += 1
            elif sel._const_sz == None:
                mutation_paths.append(curr_path)
                stats[Fields.OCTET_STRING]['unbound'] += 1

        # Note: This case should never happen for RRC DCCH Message
        if sel.TYPE is TYPE_BIT_STR and Fields.BIT_STRING in targets:
            if sel._const_sz != None and sel._const_sz.lb != sel._const_sz.ub:
                mutation_paths.append(curr_path)
                stats[Fields.BIT_STRING]['bound'] += 1
            elif sel._const_sz == None:
                mutation_paths.append(curr_path)
                stats[Fields.BIT_STRING]['unbound'] += 1

    # OCTET STRING with no continuation
    elif sel.TYPE is TYPE_OCT_STR and Fields.OCTET_STRING in targets:
        if sel._const_sz != None and sel._const_sz.lb != sel._const_sz.ub:
            mutation_paths.append(curr_path)
            stats[Fields.OCTET_STRING]['bound'] += 1
        elif sel._const_sz == None:
            mutation_paths.append(curr_path)
            stats[Fields.OCTET_STRING]['unbound'] += 1
        else:
            pass

    # BIT STRING with no continuation
    elif sel.TYPE is TYPE_BIT_STR and Fields.BIT_STRING in targets:
        if sel._const_sz != None and sel._const_sz.lb != sel._const_sz.ub:
            mutation_paths.append(curr_path)
            stats[Fields.BIT_STRING]['bound'] += 1
        elif sel._const_sz == None:
            mutation_paths.append(curr_path)
            stats[Fields.BIT_STRING]['unbound'] += 1
        else:
            pass

    elif sel.TYPE is TYPE_INT and Fields.INTEGER in targets:
        ie_range = sel._const_val.root[0]

        if type(ie_range) == int:
            # Integer is constant
            # TODO Check what mutation can be appplied in this case
            ie_lb = ie_range
            ie_ub = ie_range
        else:
            ie_lb = ie_range.lb
            ie_ub = ie_range.ub

        # Pick random value between lb and ub
        r = ie_ub - ie_lb + 1

        if r & (r - 1) != 0 and Fields.INTEGER in targets:
            mutation_paths.append(curr_path)
            stats[Fields.INTEGER]['bound'] += 1
    else:
        assert (sel.TYPE in TYPES_BASIC + TYPES_EXT)
    #
    if root:
        # print(f'Root {ies}')
        del sel._proto_recur, sel._proto_path
    ies.add(sel._name)
    return recur, stats, mutation_paths, ies


def sum_stats(targets, stats):
    total = 0
    for t in targets:
        total += stats[t]['bound'] + stats[t]['unbound']
    return total


def get_target_field_count(targets, w_recur=False):
    message = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message
    recur, stats, _, _ = get_stats(
        message, w_opt=True, targets=targets)
    
    # with open("all_stats_paths.txt", "w") as f:
    #     f.write(str(paths))
  
    if not w_recur and Fields.OCTET_STRING in targets:
        stats[Fields.OCTET_STRING]['unbound'] -= len(recur)
    return sum_stats(targets, stats)


def get_recursif_field_paths(targets, optional=True):
    message = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message
    recur = get_stats(
        message, w_opt=optional, targets=targets)[0]
    filtered_recur = []
    for r in recur:
        filtered_recur.append(list(filter(lambda x: x is not None, r)))
    return filtered_recur


def get_stats_mutation_paths(targets, w_recur=False, w_opt=True):
    message = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message
    return get_stats(
        message, w_opt=w_opt, targets=targets)[-1]

def get_total_ie_count():
    message = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message
    recur, _, _, ies = get_stats(
        message, w_opt=True, targets=[])
    
    # Used for analyzing the IEs
    if False:
        print("recur:")
        print(recur)
        exit(-1)
        if True:
            print("Total IE count")
            print("==============")
            sorted_set = sorted(ies)
            print(sorted_set)
            print(len(sorted_set))
            with open('Total_list_of_IEs_sorted.json', 'w') as f:
                json.dump(sorted_set, f)
            with open('Total_list_of_IEs_sorted.csv', 'w', newline='') as f:
                csv_writer = csv.writer(f)
                for ie in sorted_set:
                    csv_writer.writerow([ie])
            exit(-1)
    return len(ies)


if __name__ == '__main__':
    message = RRCLTE_R17.EUTRA_RRC_Definitions.DL_DCCH_Message
    targets = [Fields.OCTET_STRING, Fields.BIT_STRING]
    recur, stats, mutations, ies = get_stats(
        message, w_opt=True, targets=targets)


    print(len(ies))
    # print(recur)
    # print(stats)

