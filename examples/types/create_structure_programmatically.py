"""
summary: create & populate a structure

description:
  Usage of the API to create & populate a structure with
  members of different types.

author: Gergely Erdelyi (gergely.erdelyi@d-dome.net)

level: intermediate
"""

#---------------------------------------------------------------------
# Structure test
#
# This script demonstrates how to create structures and populate them
# with members of different types.
#---------------------------------------------------------------------

import ida_typeinf

import idc

tif = ida_typeinf.tinfo_t()
if tif.get_named_type(None, "mystr1"):
    ida_typeinf.del_named_type(None, "mystr1", ida_typeinf.NTF_TYPE)
ida_typeinf.idc_parse_types("struct mystr1 { };", 0)
if not tif.get_named_type(None, "mystr1"):
    print("Error retrieving mystr1")
print("%x" % tif.get_ordinal())

# Test simple data types
simple_types_data = [
    (ida_typeinf.BTF_BYTE, 1),
    (ida_typeinf.BTF_INT16, 2),
    (ida_typeinf.BTF_UINT32, 4),
    (ida_typeinf.BTF_INT64, 8),
    (ida_typeinf.BTF_INT128, 16),
    (ida_typeinf.BTF_FLOAT, 4),
    (ida_typeinf.BTF_DOUBLE, 8),
    (ida_typeinf.BTF_TBYTE, 10),
]

for i, tpl in enumerate(simple_types_data):
    t, nsize = tpl
    udm = ida_typeinf.udm_t(f"t{i:02d}", t, tif.get_unpadded_size() * 8)
    print(f"t{t:x}:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)))

repr_ = ida_typeinf.value_repr_t()
repr_.set_vtype(ida_typeinf.FRB_NUMO)
print("Set member representation to octal:",
      ida_typeinf.tinfo_errstr(tif.set_udm_repr(3, repr_)))

# Test ASCII type
udm = ida_typeinf.udm_t("tascii", ida_typeinf.BTF_INT64, tif.get_size() * 8)
udm.type.parse('char tascii[8] __strlit(C,"windows-1252");')
print(f"{udm.name}:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)))

# Test struct member type by preparing the whole structure at once
mtif = ida_typeinf.tinfo_t()
if mtif.get_named_type(None, "mystr2"):
    ida_typeinf.del_named_type(None, "mystr2", ida_typeinf.NTF_TYPE)

mudt = ida_typeinf.udt_type_data_t()
mudt.name = "mystr2"
tif_btf_int = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT)
mudt.add_member("member1", tif_btf_int)
mudt.add_member("member2", tif_btf_int)
mtif.create_udt(mudt)
print("Struct 2:",
      ida_typeinf.tinfo_errstr(mtif.set_named_type(None, "mystr2")))

# Test structure member
udm = ida_typeinf.udm_t("tstruct", mtif, tif.get_unpadded_size() * 8)
print("Struct member:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)))

if not mtif.create_ptr(mtif):
    print("Error while creating structure pointer")

# Test pointer to structure
udm = ida_typeinf.udm_t("strptr", mtif, tif.get_unpadded_size() * 8)
print("Strptr:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)))

# Test structure offset
udm = ida_typeinf.udm_t("tstroff", mtif, tif.get_unpadded_size() * 8)
udm.type.parse("int tstroff __stroff(mystr2);")
print("Stroff:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)))

# Test offset types
udm = ida_typeinf.udm_t("toffset", mtif, tif.get_unpadded_size() * 8)
udm.type.parse("void *toffset;")
print("Offset:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)))

# Test C bitfield types
btif = ida_typeinf.tinfo_t()
bf_nbits = 2
btif.create_bitfield(4, bf_nbits, True)  # unsigned __int32 : 2
udm = ida_typeinf.udm_t("tbitfield", btif, tif.get_unpadded_size() * 8)
# Need to set value to width, otherwise getting "Bitfield: bad size"
udm.size = bf_nbits
print("Bitfield:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)))

# Print the expanded structure
pflags = (ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_DEF
          | ida_typeinf.PRTYPE_MULTI)
print(tif._print(tif.get_type_name(), pflags))
if mtif.get_named_type(None, "mystr2"):
    print(mtif._print(mtif.get_type_name(), pflags))

print("Done")
