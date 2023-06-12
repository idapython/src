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

import ida_struct
import ida_idaapi
import ida_bytes
import ida_nalt

import idc

sid = ida_struct.get_struc_id("mystr1")
if sid != -1:
    idc.del_struc(sid)
sid = ida_struct.add_struc(ida_idaapi.BADADDR, "mystr1", 0)
print("%x" % sid)

# Test simple data types
simple_types_data = [
    (ida_bytes.FF_BYTE, 1),
    (ida_bytes.FF_WORD, 2),
    (ida_bytes.FF_DWORD, 4),
    (ida_bytes.FF_QWORD, 8),
    (ida_bytes.FF_TBYTE, 10),
    (ida_bytes.FF_OWORD, 16),
    (ida_bytes.FF_FLOAT, 4),
    (ida_bytes.FF_DOUBLE, 8),
    (ida_bytes.FF_PACKREAL, 10),
]
for i, tpl in enumerate(simple_types_data):
    t, nsize = tpl
    print("t%x:"% ((t|ida_bytes.FF_DATA) & 0xFFFFFFFF),
          idc.add_struc_member(sid, "t%02d"%i, ida_idaapi.BADADDR, (t|ida_bytes.FF_DATA )&0xFFFFFFFF, -1, nsize))

# Test ASCII type
print("ASCII:", idc.add_struc_member(sid, "tascii", -1, ida_bytes.FF_STRLIT|ida_bytes.FF_DATA, ida_nalt.STRTYPE_C, 8))

# Test struc member type
msid = ida_struct.get_struc_id("mystr2")
if msid != -1:
    idc.del_struc(msid)
msid = idc.add_struc(-1, "mystr2", 0)
print(idc.add_struc_member(msid, "member1", -1, (ida_bytes.FF_DWORD|ida_bytes.FF_DATA )&0xFFFFFFFF, -1, 4))
print(idc.add_struc_member(msid, "member2", -1, (ida_bytes.FF_DWORD|ida_bytes.FF_DATA )&0xFFFFFFFF, -1, 4))

msize = ida_struct.get_struc_size(msid)
print("Struct:", idc.add_struc_member(sid, "tstruct", -1, ida_bytes.FF_STRUCT|ida_bytes.FF_DATA, msid, msize))
print("Stroff:", idc.add_struc_member(sid, "tstroff", -1, ida_bytes.stroff_flag()|ida_bytes.FF_DWORD, msid, 4))

# Test offset types
print("Offset:", idc.add_struc_member(sid, "toffset", -1, ida_bytes.off_flag()|ida_bytes.FF_DATA|ida_bytes.FF_DWORD, 0, 4))
print("Offset:", idc.set_member_type(sid, 0, ida_bytes.off_flag()|ida_bytes.FF_DATA|ida_bytes.FF_DWORD, 0, 4))

print("Done")
