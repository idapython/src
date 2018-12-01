from __future__ import print_function
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


class ColorChanger(action_handler_t):
    def __init__(self, graph):
        action_handler_t.__init__(self)
        self.graph = graph

    def activate(self, ctx):
        self.graph.color = self.graph.color ^ 0xffffff
        self.graph.Refresh()
        return 1

    def update(self, ctx):
        return AST_ENABLE_ALWAYS


class MyGraph(GraphViewer):
    def __init__(self, funcname, result):
        self.title = "call graph of " + funcname
        GraphViewer.__init__(self, self.title)
        self.funcname = funcname
        self.result = result
        self.color = 0xff00ff

    def OnRefresh(self):
        self.Clear()
        id = self.AddNode((self.funcname, self.color))
        for x in self.result.keys():
            callee = self.AddNode((x, self.color))
            self.AddEdge(id, callee)

        return True

    def OnGetText(self, node_id):
        return self[node_id]

    def OnPopup(self, form, popup_handle):
        # graph closer
        actname = "graph_closer:%s" % self.title
        desc = action_desc_t(actname, "Close: %s" % self.title, GraphCloser(self))
        attach_dynamic_action_to_popup(form, popup_handle, desc)

        # color changer
        actname = "color_changer:%s" % self.title
        desc = action_desc_t(actname, "Change colors: %s" % self.title, ColorChanger(self))
        attach_dynamic_action_to_popup(form, popup_handle, desc)


def show_graph():
    f = idaapi.get_func(here())
    if not f:
        print("Must be in a function")
        return
    # Iterate through all function instructions and take only call instructions
    result = {}
    tmp = idaapi.insn_t()
    for x in [x for x in FuncItems(f.start_ea) if (idaapi.decode_insn(tmp, x) and idaapi.is_call_insn(tmp))]:
        for xref in XrefsFrom(x, idaapi.XREF_FAR):
            if not xref.iscode: continue
            t = get_func_name(xref.to)
            if not t:
                t = hex(xref.to)
            result[t] = True
    g = MyGraph(get_func_name(f.start_ea), result)
    if g.Show():
        return g
    else:
        return None

g = show_graph()
if g:
    print("Graph created and displayed!")
