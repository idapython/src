import idaapi
import idc
from idaapi import Choose2

def parse_pte(str):
    try:
        parse_pte.re
    except:
        parse_pte.re = re.compile('PDE at ([0-9a-f]+)\s*PTE at ([0-9a-f]+)\ncontains ([0-9a-f]+)\s*contains ([0-9a-f]+)\npfn ([0-9]+)\s*([^ ]+)\s*pfn ([0-9a-f]+)\s*([^\r\n]+)', re.I | re.M)
        parse_pte.items = ('pde', 'pte', 'pdec', 'ptec', 'pdepfn', 'pdepfns', 'ptepfn', 'ptepfns')

    m = parse_pte.re.search(s)
    r = {}
    for i in range(0, len(parse_pte.items)):
        r[parse_pte.items[i]] = m.group(i+1)
    return r

class MyChoose2(Choose2):

    def __init__(self, title, ea1, ea2):
        Choose2.__init__(self, title, [ ["VA", 10], ["PTE attr", 30] ])
        self.ea1 = ea1
        self.ea2 = ea2
        self.n = 0
        self.icon = 5
        self.items = []
        self.Refresh()
        self.selcount = 0

    def OnGetLine(self, n):
        print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        self.Refresh()
        return n

    def OnRefresh(self, n):
        print("refresh %d" % n)
        return n

    def Refresh(self):
        items = []
        PG = 0x1000
        ea1 = self.ea1
        npages = (self.ea2 - ea1) / PG
        for i in range(npages):
            r = idc.SendDbgCommand("!pte %x" % ea1)
            if not r:
                return False
            r = parse_pte(r)
            items.append([hex(ea1), r['ptepfns']])
            ea1 += PG

        self.items = items
        print(self.items)
        return True

    @staticmethod
    def Execute(ea1, ea2):
        c = MyChoose2("PTE Viewer [%x..%x]" % (ea1, ea2), ea1, ea2)
        return (c, c.Show())


def DumpPTE(ea1, ea2):
    items = []
    PG = 0x1000
    npages = (ea2 - ea1) / PG
    for i in range(npages):
        r = idc.SendDbgCommand("!pte %x" % ea1)
        if not r:
            return False
        print r
        r = parse_pte(r)
        print("VA: %08X  PTE: %s PDE: %s" % (ea1, r['ptepfns'], r['pdepfns']))
        ea1 += PG

def DumpSegPTE(ea):
    DumpPTE(idc.SegStart(ea), idc.SegEnd(ea))

DumpSegPTE(here())

#MyChoose2.Execute(0xF718F000, 0xF718F000+0x1000)

