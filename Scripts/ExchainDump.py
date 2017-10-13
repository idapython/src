"""

This script shows how to send debugger commands and use the result in IDA

Copyright (c) 1990-2009 Hex-Rays
ALL RIGHTS RESERVED.

"""

import idc
import re
import ida_kernwin
from ida_kernwin import Choose

# class to store parsed results
class exchain:
    def __init__(self, m):
        self.name       = m.group(1)
        self.addr       = int(m.group(2), 16)

# Chooser class
class MyChoose(Choose):
    def __init__(self, title, items):
        Choose.__init__(self, title, [ ["Address", 16], ["Name", 250] ])
        self.items = items

    def OnGetLine(self, n):
        o = self.items[n]
        line = []
        line.append("%08X" % o.addr)
        line.append("%s" % o.name)
        return line

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        o = self.items[n]
        Jump(o.addr)
        return (Choose.NOTHING_CHANGED, )

# main
def main():
    s = idc.eval('send_dbg_command("!exchain")')
    if "IDC_FAILURE" in s:
        return (False, "Cannot execute the command")

    matches = re.finditer(r'[^:]+: ([^\(]+) \(([^\)]+)\)\n', s)
    L = []
    for x in matches:
        L.append(exchain(x))
    if not L:
        return (False, "Nothing to display: Could parse the result!")

    # Get a Choose instance
    chooser = MyChoose("Exchain choose", L)
    # Run the chooser
    chooser.Show()
    return (True, "Success!")
ok, r = main()
if not ok:
    print r
