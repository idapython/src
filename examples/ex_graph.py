# -----------------------------------------------------------------------
# This is an example illustrating how to use the user graphing functionality
# in Python
# (c) Hex-Rays
#
from idaapi import *

class GraphCloser(action_handler_t):
    def __init__(self, graph):
        action_handler_t.__init__(self)
        self.graph = graph

    def activate(self, ctx):
        self.graph.Close()

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class MyGraph(GraphViewer):
    def __init__(self, funcname, result):
        self.title = "call graph of " + funcname
        GraphViewer.__init__(self, self.title)
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

    def Show(self):
        if not GraphViewer.Show(self):
            return False
        actname = "graph_closer:%s" % self.title
        register_action(action_desc_t(actname, "Close %s" % self.title, GraphCloser(self)))
        attach_action_to_popup(self.GetTCustomControl(), None, actname)
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