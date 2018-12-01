from __future__ import print_function

import ida_kernwin
import ida_segment
import ida_dbg

def parse_pte(s):
    try:
        parse_pte.re
    except:
        parse_pte.re = re.compile('PDE at ([0-9a-f]+)\s*PTE at ([0-9a-f]+)\ncontains ([0-9a-f]+)\s*contains ([0-9a-f]+)\npfn ([0-9]+)\s*([^ ]+)\s*pfn ([0-9a-f]+)\s*([^\r\n]+)', re.I | re.M)
        parse_pte.items = ('pde', 'pte', 'pdec', 'ptec', 'pdepfn', 'pdepfns', 'ptepfn', 'ptepfns')

    m = parse_pte.re.search(s)
    if not m:
        return None
    r = {}
    for i in range(0, len(parse_pte.items)):
        r[parse_pte.items[i]] = m.group(i+1)
    return r

class MyChoose(ida_kernwin.Choose):

    def __init__(self, title, ea1, ea2):
        ida_kernwin.Choose.__init__(self, title, [ ["VA", 10], ["PTE attr", 30] ])
        self.ea1 = ea1
        self.ea2 = ea2
        self.icon = 5
        self.items = []
        self.Refresh()

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnRefresh(self, n):
        self.Refresh()
        return (ida_kernwin.Choose.ALL_CHANGED, )

    def Refresh(self):
        items = []
        PG = 0x1000
        ea1 = self.ea1
        npages = (self.ea2 - ea1) / PG
        for i in range(npages):
            ok, r = ida_dbg.send_dbg_command("!pte %x" % ea1)
            if not ok:
                return False
            r = parse_pte(r)
            if r:
                items.append([hex(ea1), r['ptepfns']])
            ea1 += PG

        self.items = items
        print(self.items)
        return True

    @staticmethod
    def Execute(ea1, ea2):
        c = MyChoose("PTE Viewer [%x..%x]" % (ea1, ea2), ea1, ea2)
        return (c, c.Show())


def DumpPTE(ea1, ea2):
    items = []
    PG = 0x1000
    npages = (ea2 - ea1) / PG
    for i in range(npages):
        ok, r = ida_dbg.send_dbg_command("!pte %x" % ea1)
        if not ok:
            return False
        r = parse_pte(r)
        if r:
            print("VA: %08X  PTE: %s PDE: %s" % (ea1, r['ptepfns'], r['pdepfns']))
        ea1 += PG

def DumpSegPTE(ea):
    s = ida_segment.getseg(ea)
    DumpPTE(s.start_ea, s.end_ea)

DumpSegPTE(here())

#MyChoose.Execute(0xF718F000, 0xF718F000+0x1000)

