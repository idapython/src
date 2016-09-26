"""

This script shows how to send debugger commands and use the result in IDA

Copyright (c) 1990-2009 Hex-Rays
ALL RIGHTS RESERVED.

"""

import idc
from idaapi import Choose

import re

# class to store parsed results
class memva:
    def __init__(self, m):
        self.base       = int(m.group(1), 16)
        self.regionsize = int(m.group(2), 16)
        self.state      = int(m.group(3), 16)
        self.statestr   = m.group(4).strip()
        self.protect    = int(m.group(5), 16)
        self.protectstr = m.group(6).strip()
        if m.group(7):
            self.type       = int(m.group(8), 16)
            self.typestr    = m.group(9).strip()
        else:
            self.type       = 0
            self.typestr    = ""
    def __str__(self):
        return "(Base %08X; RegionSize: %08X; State: %08X/%10s; protect: %08X/%10s; type: %08X/%10s)" % (
                self.base, self.regionsize, self.state,
                self.statestr, self.protect,
                self.protectstr, self.type, self.typestr)

# Chooser class
class MemChoose(Choose):
    def __init__(self, list, title):
        Choose.__init__(self, list, title)
        self.width = 250

    def enter(self, n):
        o = self.list[n-1]
        idc.Jump(o.base)

# main
def main():
    s = idc.Eval('SendDbgCommand("!vadump")')
    if "IDC_FAILURE" in s:
        return (False, "Cannot execute the command")

    matches = re.finditer(r'BaseAddress:\s*?(\w+?)\n' \
                          +'RegionSize:\s*?(\w*?)\n' \
                          +'State:\s*?(\w*?)\s*?(\w*?)\n' \
                          +'Protect:\s*?(\w*?)\s*?(\w*?)\n' \
                          +'(Type:\s*?(\w*?)\s*?(\w*?)\n)*', s)
    L = []
    for x in matches:
        L.append(memva(x))
    if not L:
        return (False, "Nothing to display: Could not parse the result!")

    # Get a Choose instance
    chooser = MemChoose(L, "Memory choose")
    # Run the chooser
    chooser.choose()
    return (True, "Success!")
r = main()
if not r[0]:
    print r[1]
