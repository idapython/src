"""
summary: create a structure programmatically

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we create a structure by building it member by member.

level: intermediate
"""
import ida_typeinf

# Delete the structure in case it already exist.
ida_typeinf.del_named_type(None, "pcaprec_hdr_s", ida_typeinf.NTF_TYPE)

print("Add udt members")
# Create and fill the udt.
field_list = [("ts_sec", ida_typeinf.BTF_UINT32),
              ("ts_usec", ida_typeinf.BTF_UINT32),
              ("incl_len", ida_typeinf.BTF_UINT32),
              ("orig_len", ida_typeinf.BTF_UINT32)]
udt = ida_typeinf.udt_type_data_t()
for (name, _type) in field_list:
    udm = udt.add_member(name, ida_typeinf.tinfo_t(_type))
    print("udm:", udm.name, udm.size, udm.offset)

print("Changing udm from last iteration")
udm.name = "upd_udm"
udm.offset = 3
print("Compare updated udm with the last in the udt")
last = udt.back()
print("udm at the end:", last.name, last.offset)
print("Equal:", last == udm)
print("But not the same object:", last is not udm)

# Actually create the type
tif = ida_typeinf.tinfo_t()
if tif.create_udt(udt):
    print("Created:",
          ida_typeinf.tinfo_errstr(tif.set_named_type(None, "pcaprec_hdr_s")))

print("\nCheck that the layout is correct")
udt = ida_typeinf.udt_type_data_t()
if tif.get_udt_details(udt):
    print(f"Listing the pcaprec_hdr_s structure {udt.size()} field names:")
    for idx, udm in enumerate(udt):
        print(f"Field {idx}: {udm.name}, "
              f"size: {udm.size}, offset: {udm.offset}")
        idx += 1
else:
    print("Unable to get udt details for structure")
