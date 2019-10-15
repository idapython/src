from __future__ import print_function
#---------------------------------------------------------------------
# Structure test
#
# This script demonstrates how to create structures and populate them
# with members of different types.
#
# Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#---------------------------------------------------------------------
from idaapi import stroffflag, offflag

sid = get_struc_id("mystr1")
if sid != -1:
    del_struc(sid)
sid = add_struc(-1, "mystr1", 0)
print("%x" % sid)

# Test simple data types
simple_types = [ FF_BYTE, FF_WORD, FF_DWORD, FF_QWORD, FF_TBYTE, FF_OWORD, FF_FLOAT, FF_DOUBLE, FF_PACKREAL ]
simple_sizes = [ 1, 2, 4, 8, 10, 16, 4, 8, 10 ]

i = 0
for t,nsize in zip(simple_types, simple_sizes):
    print("t%x:"% ((t|FF_DATA)&0xFFFFFFFF), add_struc_member(sid, "t%02d"%i, BADADDR, (t|FF_DATA )&0xFFFFFFFF, -1, nsize))
    i+=1

# Test ASCII type
print("ASCII:", add_struc_member(sid, "tascii", -1, FF_STRLIT|FF_DATA, STRTYPE_C, 8))

# Test enum type - Add a defined enum name or load MACRO_WMI from a type library.
#eid = get_enum("MACRO_WMI")
#print("Enum:", add_struc_member(sid, "tenum", BADADDR, FF_0ENUM|FF_DATA|FF_DWORD, eid, 4))

# Test struc member type
msid = get_struc_id("mystr2")
if msid != -1:
    del_struc(msid)
msid = add_struc(-1, "mystr2", 0)
print(add_struc_member(msid, "member1", -1, (FF_DWORD|FF_DATA )&0xFFFFFFFF, -1, 4))
print(add_struc_member(msid, "member2", -1, (FF_DWORD|FF_DATA )&0xFFFFFFFF, -1, 4))

msize = get_struc_size(msid)
print("Struct:", add_struc_member(sid, "tstruct", -1, FF_STRUCT|FF_DATA, msid, msize))
print("Stroff:", add_struc_member(sid, "tstroff", -1, stroffflag()|FF_DWORD, msid, 4))

# Test offset types
print("Offset:", add_struc_member(sid, "toffset", -1, offflag()|FF_DATA|FF_DWORD, 0, 4))
print("Offset:", set_member_type(sid, 0, offflag()|FF_DATA|FF_DWORD, 0, 4))

print("Done")
