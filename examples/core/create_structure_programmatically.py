"""
summary: programmatically create & populate a structure

description:
  Usage of the API to create & populate a structure with
  members of different types.

author: Gergely Erdelyi (gergely.erdelyi@d-dome.net)
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
ida_typeinf.idc_parse_types('struct mystr1 { };', 0)
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

udm = ida_typeinf.udm_t()
for i, tpl in enumerate(simple_types_data):
    t, nsize = tpl
    udm.name = "t%02d" % i
    udm.size = nsize * 8
    udm.type = ida_typeinf.tinfo_t(t)
    udm.offset = tif.get_unpadded_size() * 8
    print("t%x:"% t,
          ida_typeinf.tinfo_errstr(tif.add_udm(udm)) )

repr = ida_typeinf.value_repr_t()
repr.set_vtype(ida_typeinf.FRB_NUMO)
print("Set member representation to octal:",
    ida_typeinf.tinfo_errstr(tif.set_udm_repr(3, repr)) )

# Test ASCII type
udm = ida_typeinf.udm_t()
udm.name = "tascii"
udm.size = 8 * 8
udm.type.parse('char tascii[8] __strlit(C,"windows-1252");') # no other way?
udm.offset = tif.get_size() * 8
print("%s:"% udm.name,
      ida_typeinf.tinfo_errstr(tif.add_udm(udm)) )

# Test struct member type by preparing the whole structure at once
mtif = ida_typeinf.tinfo_t()
if mtif.get_named_type(None, "mystr2"):
    ida_typeinf.del_named_type(None, "mystr2", ida_typeinf.NTF_TYPE)

mudt = ida_typeinf.udt_type_data_t()
mudt.name="mystr2"
mudm = ida_typeinf.udm_t()
mudm.name="member1"
mudm.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT)
mudt.push_back(mudm)
mudm.name="member2"
mudt.push_back(mudm)
mtif.create_udt(mudt)
print("Struct 2:", ida_typeinf.tinfo_errstr(mtif.set_named_type(None, "mystr2")) )

#Test structure member
udm.size = mtif.get_size() * 8
udm.offset = tif.get_unpadded_size() * 8
udm.name = "tstruct"
udm.type = mtif
print("Struct member:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)) )

#Test pointer to structure
udm.name = "strptr"
udm.size = 32
udm.offset = tif.get_unpadded_size() * 8
if not mtif.create_ptr(mtif):
    print("Error while creating structure pointer")
udm.type = mtif
print("Strptr:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)) )

#Test structure offset
udm.name = "tstroff"
udm.size = 32
udm.offset = tif.get_unpadded_size() * 8
udm.type.parse("int tstroff __stroff(mystr2);")
print("Stroff:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)) )

# Test offset types
udm.name = "toffset"
udm.size = 32
udm.offset = tif.get_unpadded_size() * 8
udm.type.parse("void *toffset;")
print("Offset:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)) )

# Test C bitfield types
udm.name = "tbitfield"
udm.offset = tif.get_unpadded_size() * 8
btif = ida_typeinf.tinfo_t()
btif.create_bitfield(4, 2, True) # unsigned __int32 : 2
udm.size = 2
udm.type = btif
print("Bitfield:", ida_typeinf.tinfo_errstr(tif.add_udm(udm)) )

# Print the expanded structure
pflags = ida_typeinf.PRTYPE_TYPE|ida_typeinf.PRTYPE_DEF|ida_typeinf.PRTYPE_MULTI
print(tif._print(tif.get_type_name(), pflags))
if mtif.get_named_type(None, "mystr2"):
    print(mtif._print(mtif.get_type_name(), pflags))

print("Done")
