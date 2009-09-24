import idaapi
import idautils
import idc

class MyChoose2(Choose2):

    def __init__(self, title):
        Choose2.__init__(self, title, [ ["Address", 10 | Choose2.CHCOL_HEX], ["Name", 30 | Choose2.CHCOL_PLAIN] ])
        self.n = 0
        self.icon = 41
        self.PopulateItems()

    def PopulateItems(self):
        self.items = [ [hex(x), GetFunctionName(x), x] for x in idautils.Functions() ]
        
    def OnClose(self):
        print "closed ", self.title

    def OnSelectLine(self, n):
        idc.Jump(self.items[n][2])

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnDeleteLine(self, n):
        ea = self.items[n][2]
        idc.DelFunction(ea)
        return n

    def OnRefresh(self, n):
        self.PopulateItems()
        return n

c = MyChoose2("My functions list")
c.Show()