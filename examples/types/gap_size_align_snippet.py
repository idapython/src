"""
summary: utilities to detect structure gaps & alignment

description:
    The goal of this script is to illustrate ways to detect gaps & alignments
    in structures, from a structure name & (byte) offset.

level: intermediate
"""

import ida_typeinf
import ida_range

# Get size of struct member + alignment
def get_member_size_align(struct_name, byte_offset):
    tif = ida_typeinf.get_idati().get_named_type(struct_name)
    if tif:
        _, udm = tif.get_udm_by_offset(byte_offset * 8)
        if udm:
            return udm.type.get_size(), udm.effalign
    return -1, -1

## Check if offset is part of a gap
def is_struct_gap(struc_name, byte_offset):
    tif = ida_typeinf.get_idati().get_named_type(struc_name)
    if not tif:
        return False
    rs = ida_range.rangeset_t()
    tif.calc_gaps(rs)
    for i in range(rs.nranges()):
        r = rs.getrange(i)
        if r.start_ea <= byte_offset < r.end_ea:
            return True
    return False
