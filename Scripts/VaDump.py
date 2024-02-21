"""

This script shows how to send debugger commands and use the result in IDA

Copyright (c) 1990-2024 Hex-Rays
ALL RIGHTS RESERVED.

"""
from __future__ import print_function

import re

import ida_kernwin

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

# Chooser class
class MemChoose(ida_kernwin.Choose):
    def __init__(self, title, items):
        headers = []
        headers.append(["Base", 10])
        headers.append(["RegionSize", 10])
        headers.append(["State", 20])
        headers.append(["Protect", 20])
        headers.append(["Type", 20])
        ida_kernwin.Choose.__init__(self, title, headers)
        self.items = items

    def OnGetLine(self, n):
        o = self.items[n]
        line = []
        line.append("%08X" % o.base)
        line.append("%08X" % o.regionsize)
        line.append("%08X/%10s" % (o.state, o.statestr))
        line.append("%08X/%10s" % (o.protect, o.protectstr))
        line.append("%08X/%10s" % (o.type, o.typestr))
        return line

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        o = self.items[n]
        ida_kernwin.jumpto(o.base)
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

# main
def main():
    ok, s = ida_dbg.send_dbg_command("!vadump")
    if not ok:
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
    chooser = MemChoose("Memory choose", L)
    # Run the chooser
    chooser.Show()
    return (True, "Success!")
r = main()
if not r[0]:
    print(r[1])
