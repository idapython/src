# -----------------------------------------------------------------------
# This is an example illustrating how to use the graphing functionality in Python
# (c) Hex-Rays
#
from idaapi import GraphViewer

class MyGraph(GraphViewer):
    def __init__(self, funcname, result):
        GraphViewer.__init__(self, "call graph of " + funcname)
        self.funcname = funcname
        self.result = result

    def OnRefresh(self):
        self.Clear()
        id = self.AddNode(self.funcname)
        for x in self.result.keys():
            callee = self.AddNode(x)
            self.AddEdge(id, callee)

        return True

    def OnGetText(self, node_id):
        return str(self[node_id])

    def OnCommand(self, cmd_id):
        """
        Triggered when a menu command is selected through the menu or its hotkey
        @return: None
        """
        if self.cmd_close == cmd_id:
            self.Close()
            return

        print "command:", cmd_id

    def Show(self):
        if not GraphViewer.Show(self):
            return False
        self.cmd_close = self.AddCommand("Close", "F2")
        if self.cmd_close == 0:
            print "Failed to add popup menu item!"
        return True

def show_graph():
    f = idaapi.get_func(here())
    if not f:
        print "Must be in a function"
        return
    # Iterate through all function instructions and take only call instructions
    result = {}
    for x in [x for x in FuncItems(f.startEA) if idaapi.is_call_insn(x)]:
        for xref in XrefsFrom(x, idaapi.XREF_FAR):
            if not xref.iscode: continue
            t = GetFunctionName(xref.to)
            if not t:
                t = hex(xref.to)
            result[t] = True
    g = MyGraph(GetFunctionName(f.startEA), result)
    if g.Show():
        return g
    else:
        return None

g = show_graph()
if g:
    print "Graph created and displayed!"