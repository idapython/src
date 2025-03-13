"""
summary: create a structure with bitfield members

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we:
     * Create a bitfield structure. In the present case the bitfield is an int32
    made of three 'members' spanning it entirely:
        bit0->bit19: bf1
        bit20->bit25: bf2
        bit26->bit31: bf3
     * For each member create a repeatable comment.

level: intermediate
"""
import ida_typeinf

# Create and fill the containing user data type.
udt = ida_typeinf.udt_type_data_t()
for name, offset, size, bitfield_info in [
    ("bf1", 0, 20, (4, 20)),
    ("bf2", 20, 6, (4, 6)),
    ("bf3", 26, 6, (4, 6))
]:
    bf_bucket_size, bf_nbits = bitfield_info
    bftif = ida_typeinf.tinfo_t()
    bftif.create_bitfield(bf_bucket_size, bf_nbits)
    udm = ida_typeinf.udm_t(name, bftif)
    udm.offset = offset
    udm.size = size
    udm.cmt = f"Bitfield member {name}"
    udt.push_back(udm)

# Create the type.
tif = ida_typeinf.tinfo_t()
if tif.create_udt(udt):
    print(f"{tif._print()}")
