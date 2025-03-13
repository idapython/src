"""
summary: inject a member in the middle of a structure

description:
    This sample will retrieve the type info object by its name,
    find the member at the specified offset, and insert a
    new member right before it

level: intermediate
"""
import ida_typeinf

def insert_gap(struct_name: str, byte_offset: int, member_type: ida_typeinf.tinfo_t):

    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, struct_name):
        print(f"Unable to get {struct_name} structure.")
        return False

    idx, existing_udm = tif.get_udm_by_offset(byte_offset * 8)
    if idx < 0:
        print(f"Cannot find member at offset {byte_offset:x}")
        return False

    nbytes = member_type.get_size()
    if tif.expand_udt(idx, nbytes) != ida_typeinf.TERR_OK:
        print(f"Unable to create a gap member of {nbytes:x} bytes @ offset {byte_offset:x}")
        return False

    new_udm = udm_t("fresh_new_member", member_type)
    new_udm.offset = existing_udm.offset
    tif.add_udm(new_udm, 0, 1, idx)

    return True

if not insert_gap("_TraceLoggingMetadata_t", 8, ida_typeinf.tinfo_t(ida_typeinf.BT_INT)):
    print("Failed to insert gaps.")
else:
    print("Done.")
