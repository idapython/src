"""
summary: retrieve the strings that are present in the IDB

description:
  This uses `idautils.Strings` to iterate over the string literals
  that are present in the IDB. Contrary to @show_selected_strings,
  this will not require that the "Strings" window is opened & available.

see_also: show_selected_strings
"""

import ida_nalt
import idautils

s = idautils.Strings(False)
s.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16])
for i, v in enumerate(s):
    if v is None:
        print("Failed to retrieve string index %d" % i)
    else:
        print("%x: len=%d type=0x%x index=%d-> '%s'" % (v.ea, v.length, v.strtype, i, str(v)))
