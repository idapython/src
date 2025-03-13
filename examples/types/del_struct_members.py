"""
summary: delete structure members that fall within an offset range

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we first create a structure with many members, and then
    remove all those that fall within a range.

level: beginner
"""

import ida_typeinf
import ida_idaapi

struct_decl = """
struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
};"""

# Compute the indexes that map the range, and then trash the members
def del_range(tif, start_byte_offset, end_byte_offset):

    udm = ida_typeinf.udm_t()
    udm.offset = start_byte_offset * 8
    idx1 = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)

    udm = ida_typeinf.udm_t()
    udm.offset = end_byte_offset * 8
    idx2 = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)

    return tif.del_udms(idx1, idx2)

# Helper
def dump(message, tif):
    print(message)
    for udm in tif.iter_struct():
        print(f"\t{(udm.offset//8):04x}: {udm.name}")

# Prepare type
tif = ida_typeinf.tinfo_t(struct_decl)
dump("Initially", tif)

# Delete some members
assert(del_range(tif, 4, 16) == ida_typeinf.TERR_OK)
dump("After deleting some members", tif)

