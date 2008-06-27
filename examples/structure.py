#---------------------------------------------------------------------
# Structure test
#
# This script demonstrates how to create structures and populate them
# with members of different types.
#
# Author: Gergely Erdelyi <dyce@d-dome.net>
#---------------------------------------------------------------------
from idaapi import stroffflag, offflag

sid = GetStrucIdByName("mystr1")
if sid != -1:
    DelStruc(sid)
sid = AddStrucEx(-1, "mystr1", 0)
print "%x" % sid

# Test simple data types
simple_types = [ FF_BYTE, FF_WORD, FF_DWRD, FF_QWRD, FF_TBYT, FF_OWRD, FF_FLOAT, FF_DOUBLE, FF_PACKREAL ]
simple_sizes = [ 1, 2, 4, 8, 10, 16, 4, 8, 10 ]

i = 0
for t,nsize in zip(simple_types, simple_sizes):
    print "t%x:"% ((t|FF_DATA)&0xFFFFFFFF), AddStrucMember(sid, "t%02d"%i, BADADDR, (t|FF_DATA )&0xFFFFFFFF, -1, nsize)
    i+=1
 
# Test ASCII type
print "ASCII:", AddStrucMember(sid, "tascii", BADADDR, FF_ASCI|FF_DATA, ASCSTR_C, 8)

# Test enum type - Add a defined enum name or load MACRO_WMI from a type library.
#eid = GetEnum("MACRO_WMI")
#print "Enum:", AddStrucMember(sid, "tenum", BADADDR, FF_0ENUM|FF_DATA|FF_DWRD, eid, 4)

# Test struc member type
msid = GetStrucIdByName("mystr2")
if msid != -1:
    DelStruc(msid)
msid = AddStrucEx(-1, "mystr2", 0)
print AddStrucMember(msid, "member", BADADDR, (FF_DWRD|FF_DATA )&0xFFFFFFFF, -1, 4)

msize = GetStrucSize(msid)
print "Struct:", AddStrucMember(sid, "tstruct", BADADDR, FF_STRU|FF_DATA, msid, msize)
print "Stroff:", AddStrucMember(sid, "tstroff", BADADDR, stroffflag()|FF_DWRD, msid, 4)

# Test offset types
print "Offset:", AddStrucMember(sid, "toffset", BADADDR, offflag()|FF_DATA|FF_DWRD, 0, 4)
print "Offset:", SetMemberType(sid, 0, offflag()|FF_DATA|FF_DWRD, 0, 4)

print "Done"
