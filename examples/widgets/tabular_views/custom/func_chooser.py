"""
summary: An alternative view over the list of functions

description:
  Partially re-implements the "Functions" widget present in
  IDA, with a custom widget.

keywords: chooser, functions

see_also: choose, choose_multi, chooser_with_folders
"""

import idautils
import idc
import ida_funcs
import ida_kernwin

class my_funcs_t(ida_kernwin.Choose):

    def __init__(self, title):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [ ["Address", 10 | ida_kernwin.Choose.CHCOL_HEX],
              ["Name",    30 | ida_kernwin.Choose.CHCOL_PLAIN | ida_kernwin.Choose.CHCOL_FNAME] ])
        self.items = []
        self.icon = 41

    def OnInit(self):
        self.items = [ [hex(x), ida_funcs.get_func_name(x), x]
                       for x in idautils.Functions() ]
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnDeleteLine(self, n):
        ea = self.items[n][2]
        idc.del_func(ea)
        return (ida_kernwin.Choose.ALL_CHANGED, n)

    def OnGetEA(self, n):
        return self.items[n][2]

    def OnRefresh(self, n):
        self.OnInit()
        # try to preserve the cursor
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnClose(self):
        print("closed ", self.title)


def show_my_funcs_t(modal=False):
    c = my_funcs_t("My functions list")
    c.Show(modal=modal)

if __name__ == "__main__":
    show_my_funcs_t()

