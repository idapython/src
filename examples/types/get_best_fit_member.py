"""
summary: get member by offset, taking into account variable sized structures

description:
    The goal of this script is to provide a way to figure out
    what structure member, is most likely referenced by an offset.

    This also works for variable sized types.

level: intermediate
"""
import ida_typeinf
import ida_idaapi

def get_best_fit_member(tif, offset):
    udm = None
    if tif.is_udt():
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt):
            _, udm = udt.get_best_fit_member(offset)
    return udm

struct_str = """struct modified_pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_info[6];
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        unsigned char mybytes[8];
};"""

tif = ida_typeinf.tinfo_t(struct_str)

byte_offset = 5
udm = get_best_fit_member(tif, byte_offset)
if udm:
    print(f"Found: {udm.name}")
else:
    print(f"No member at {byte_offset}")
