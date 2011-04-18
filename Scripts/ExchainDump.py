"""

This script shows how to send debugger commands and use the result in IDA

Copyright (c) 1990-2009 Hex-Rays
ALL RIGHTS RESERVED.

"""

import idc
import re

# class to store parsed results
class exchain:
    def __init__(self, m):
        self.name       = m.group(1)
        self.addr       = int(m.group(2), 16)

    def __str__(self):
        return "%x: %s" % (self.addr, self.name)

# Chooser class
class MyChoose(Choose):
    def __init__(self, list, title):
        Choose.__init__(self, list, title)
        self.width = 250

    def enter(self, n):
        o = self.list[n-1]
        idc.Jump(o.addr)

# main
def main():
    s = idc.Eval('SendDbgCommand("!exchain")')
    if "IDC_FAILURE" in s:
        return (False, "Cannot execute the command")

    matches = re.finditer(r'[^:]+: ([^\(]+) \(([^\)]+)\)\n', s)
    L = []
    for x in matches:
        L.append(exchain(x))
    if not L:
        return (False, "Nothing to display: Could parse the result!")

    # Get a Choose instance
    chooser = MyChoose(L, "Exchain choose")
    # Run the chooser
    chooser.choose()
    return (True, "Success!")
ok, r = main()
if not ok:
    print r
