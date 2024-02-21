"""

This script shows how to send debugger commands and use the result in IDA

Copyright (c) 1990-2024 Hex-Rays
ALL RIGHTS RESERVED.

"""
from __future__ import print_function

import re

import ida_kernwin

# class to store parsed results
class exchain:
    def __init__(self, m):
        self.name = m.group(1)
        self.addr = int(m.group(2), 16)

# Chooser class
class MyChoose(ida_kernwin.Choose):
    def __init__(self, title, items):
        ida_kernwin.Choose.__init__(self, title, [ ["Address", 16], ["Name", 250] ])
        self.items = items

    def OnGetLine(self, n):
        o = self.items[n]
        return ["%08X" % o.addr, o.name]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.items[n].addr)
        return (ida_kernwin.Choose.NOTHING_CHANGED, )

def main():
    ok, s = ida_dbg.send_dbg_command("!exchain")
    if not ok:
        return (False, "Cannot execute the command (%s)" % s)

    matches = re.finditer(r'[^:]+: ([^\(]+) \(([^\)]+)\)\n', s)
    entries = [exchain(x) for x in matches]
    if not entries:
        return (False, "Nothing to display: Could parse the result!")

    # Show a list of results, and let the user possibly jump to one of those
    chooser = MyChoose("Exchain choose", entries)
    chooser.Show()
    return (True, "Success!")

ok, r = main()
if not ok:
    print(r)
