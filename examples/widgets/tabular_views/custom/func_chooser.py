from __future__ import print_function
import idautils
import idc
from ida_kernwin import Choose

class MyChoose(Choose):

    def __init__(self, title):
        Choose.__init__(
            self,
            title,
            [ ["Address", 10 | Choose.CHCOL_HEX],
              ["Name",    30 | Choose.CHCOL_PLAIN] ])
        self.items = []
        self.icon = 41

    def OnInit(self):
        self.items = [ [hex(x), get_func_name(x), x]
                       for x in idautils.Functions() ]
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnDeleteLine(self, n):
        ea = self.items[n][2]
        idc.del_func(ea)
        return (Choose.ALL_CHANGED, n)

    def OnSelectLine(self, n):
        idc.jumpto(self.items[n][2])
        return (Choose.NOTHING_CHANGED, )

    def OnRefresh(self, n):
        self.OnInit()
        # try to preserve the cursor
        return [Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnClose(self):
        print("closed ", self.title)

c = MyChoose("My functions list")
c.Show()
