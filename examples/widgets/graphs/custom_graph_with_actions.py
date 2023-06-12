"""
summary: drawing custom graphs

description:
  Showing custom graphs, using `ida_graph.GraphViewer`. In addition,
  show how to write actions that can be performed on those.

keywords: graph, actions
"""

# -----------------------------------------------------------------------
# This is an example illustrating how to use the user graphing functionality
# in Python
# (c) Hex-Rays
#

import ida_kernwin
import ida_graph
import ida_ua
import ida_idp
import ida_funcs
import ida_xref

import idautils

class _base_graph_action_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, graph):
        ida_kernwin.action_handler_t.__init__(self)
        self.graph = graph

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class GraphCloser(_base_graph_action_handler_t):
    def activate(self, ctx):
        self.graph.Close()


class ColorChanger(_base_graph_action_handler_t):
    def activate(self, ctx):
        self.graph.color = self.graph.color ^ 0xffffff
        self.graph.Refresh()
        return 1


class SelectionPrinter(_base_graph_action_handler_t):
    def activate(self, ctx):
        try:
            sel = ctx.graph_selection
        except:
            # IDA < 7.4 doesn't provide graph selection as part of
            # the action_activation_ctx_t; it needs to be queried.
            sel = ida_graph.screen_graph_selection_t()
            gv = ida_graph.get_graph_viewer(self.graph.GetWidget())
            ida_graph.viewer_get_selection(gv, sel)
        if sel:
            for s in sel:
                if s.is_node:
                    print("Selected node %d" % s.node)
                else:
                    print("Selected edge %d -> %d" % (s.elp.e.src, s.elp.e.dst))
        return 1


class MyGraph(ida_graph.GraphViewer):
    def __init__(self, funcname, result):
        self.title = "call graph of " + funcname
        ida_graph.GraphViewer.__init__(self, self.title)
        self.funcname = funcname
        self.result = result
        self.color = 0xff00ff

        #
        # for the sake of this example, here's how one can use
        # 'ida_kernwin.View_Hooks' (which can be used with all
        # "listing-like" and "graph" widgets) to be notified
        # of cursor movement, current node changes, etc...
        # in this graph.
        #
        class my_view_hooks_t(ida_kernwin.View_Hooks):
            def __init__(self, v):
                ida_kernwin.View_Hooks.__init__(self)
                self.hook()
                # let's use weakrefs, so as soon as the last ref to
                # the 'MyGraph' instance is dropped, the 'my_view_hooks_t'
                # instance hooks can be automatically un-hooked, and deleted.
                # (in other words: avoid circular reference.)
                import weakref
                self.v = weakref.ref(v)

            def view_loc_changed(self, w, now, was):
                now_node = now.renderer_info().pos.node
                was_node = was.renderer_info().pos.node
                if now_node != was_node:
                    if self.v().GetWidget() == w:
                        print("Current node now: #%d (was #%d)" % (now_node, was_node))

        self.my_view_hooks = my_view_hooks_t(self)


    def OnRefresh(self):
        self.Clear()
        id = self.AddNode((self.funcname, self.color))
        for x in self.result:
            callee = self.AddNode((x, self.color))
            self.AddEdge(id, callee)

        return True

    def OnGetText(self, node_id):
        return self[node_id]

    def OnPopup(self, widget, popup_handle):
        # graph closer
        actname = "graph_closer:%s" % self.title
        desc = ida_kernwin.action_desc_t(actname, "Close: %s" % self.title, GraphCloser(self))
        ida_kernwin.attach_dynamic_action_to_popup(None, popup_handle, desc)

        # color changer
        actname = "color_changer:%s" % self.title
        desc = ida_kernwin.action_desc_t(actname, "Change colors: %s" % self.title, ColorChanger(self))
        ida_kernwin.attach_dynamic_action_to_popup(None, popup_handle, desc)

        # selection printer
        actname = "selection_printer:%s" % self.title
        desc = ida_kernwin.action_desc_t(actname, "Print selection: %s" % self.title, SelectionPrinter(self))
        ida_kernwin.attach_dynamic_action_to_popup(None, popup_handle, desc)


def show_graph():
    f = ida_funcs.get_func(ida_kernwin.get_screen_ea())
    if not f:
        print("Must be in a function")
        return
    # Iterate through all function instructions and take only call instructions
    result = []
    tmp = ida_ua.insn_t()
    for x in [x for x in f if (ida_ua.decode_insn(tmp, x) and ida_idp.is_call_insn(tmp))]:
        xb = ida_xref.xrefblk_t()
        for xref in xb.refs_from(x, ida_xref.XREF_FAR):
            if not xref.iscode: continue
            t = ida_funcs.get_func_name(xref.to)
            if not t:
                t = hex(xref.to)
            result.append(t)
    g = MyGraph(ida_funcs.get_func_name(f.start_ea), result)
    if g.Show():
        return g
    else:
        return None

g = show_graph()
if g:
    print("Graph created and displayed!")
