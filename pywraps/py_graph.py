#<pycode(py_graph)>
import ida_idaapi
import ida_kernwin

class GraphViewer(ida_kernwin.CustomIDAMemo):
    class UI_Hooks_Trampoline(ida_kernwin.UI_Hooks):
        def __init__(self, v):
            ida_kernwin.UI_Hooks.__init__(self)
            self.hook()
            import weakref
            self.v = weakref.ref(v)

        def populating_widget_popup(self, w, popup_handle):
            my_w = self.v().GetWidget()
            if w == my_w:
                self.v().OnPopup(my_w, popup_handle)

    """This class wraps the user graphing facility provided by the graph.hpp file"""
    def __init__(self, title, close_open = False):
        """
        Constructs the GraphView object.
        Please do not remove or rename the private fields

        @param title: The title of the graph window
        @param close_open: Should it attempt to close an existing graph (with same title) before creating this graph?
        """
        self._title = title
        self._nodes = []
        self._edges = []
        self._close_open = close_open
        def _qccb(ctx, cmd_id):
            return self.OnCommand(cmd_id)
        self._quick_commands = ida_kernwin.quick_widget_commands_t(_qccb)
        ida_kernwin.CustomIDAMemo.__init__(self)
        self.ui_hooks_trampoline = self.UI_Hooks_Trampoline(self)

    def AddNode(self, obj):
        """Creates a node associated with the given object and returns the node id"""
        id = len(self._nodes)
        self._nodes.append(obj)
        return id

    def AddEdge(self, src_node, dest_node):
        """Creates an edge between two given node ids"""
        assert src_node < len(self._nodes), "Source node %d is out of bounds" % src_node
        assert dest_node < len(self._nodes), "Destination node %d is out of bounds" % dest_node
        self._edges.append( (src_node, dest_node) )

    def Clear(self):
        """Clears all the nodes and edges"""
        self._nodes = []
        self._edges = []

    def __iter__(self):
        return (self._nodes[index] for index in range(0, len(self._nodes)))

    def __getitem__(self, idx):
        """Returns a reference to the object associated with this node id"""
        if idx >= len(self._nodes):
            raise KeyError
        else:
            return self._nodes[idx]

    def Count(self):
        """Returns the node count"""
        return len(self._nodes)

    def Close(self):
        """
        Closes the graph.
        It is possible to call Show() again (which will recreate the graph)
        """
        _ida_graph.pyg_close(self)

    def Show(self):
        """
        Shows an existing graph or creates a new one

        @return: Boolean
        """
        if self._close_open:
            import ida_kernwin
            frm = ida_kernwin.find_widget(self._title)
            if frm:
                ida_kernwin.close_widget(frm, 0)
        return _ida_graph.pyg_show(self)

    def Select(self, node_id):
        """Selects a node on the graph"""
        _ida_graph.pyg_select_node(self, node_id)

    def OnRefresh(self):
        """
        Event called when the graph is refreshed or first created.
        From this event you are supposed to create nodes and edges.
        This callback is mandatory.

        @note: ***It is important to clear previous nodes before adding nodes.***
        @return: Returning True tells the graph viewer to use the items. Otherwise old items will be used.
        """
        self.Clear()

        return True

    def AddCommand(self, title, shortcut):
        return self._quick_commands.add(
            caption=title,
            flags=ida_kernwin.CHOOSER_POPUP_MENU,
            menu_index=-1,
            icon=-1,
            emb=None,
            shortcut=shortcut)

    def OnPopup(self, widget, popup_handle):
        self._quick_commands.populate_popup(widget, popup_handle)

    def OnCommand(self, cmd_id):
        return 0

    def _OnBind(self, hook):
        if hook:
            self.ui_hooks_trampoline.hook()
        else:
            self.ui_hooks_trampoline.unhook()
        super()._OnBind(hook)

#<pydoc>
#    def OnGetText(self, node_id):
#        """
#        Triggered when the graph viewer wants the text and color for a given node.
#        This callback is triggered one time for a given node (the value will be cached and used later without calling Python).
#        When you call refresh then again this callback will be called for each node.
#
#        This callback is mandatory.
#
#        @return: Return a string to describe the node text or return a tuple (node_text, node_color) to describe both text and color
#        """
#        return str(self[node_id])
#
#    def OnActivate(self):
#        """
#        Triggered when the graph window gets the focus
#        @return: None
#        """
#        print("Activated....")
#
#    def OnDeactivate(self):
#        """Triggered when the graph window loses the focus
#        @return: None
#        """
#        print("Deactivated....")
#
#    def OnHint(self, node_id):
#        """
#        Triggered when the graph viewer wants to retrieve hint text associated with a given node
#
#        @return: None if no hint is avail or a string designating the hint
#        """
#        return "hint for " + str(node_id)
#
#    def OnEdgeHint(self, src, dst):
#        """
#        Triggered when the graph viewer wants to retrieve hint text associated with a edge
#
#        @return: None if no hint is avail or a string designating the hint
#        """
#        return "hint for edge %d -> %d" % (src, dst)
#
#    def OnClose(self):
#        """Triggered when the graph viewer window is being closed
#        @return: None
#        """
#        print("Closing.......")
#
#    def OnClick(self, node_id):
#        """
#        Triggered when a node is clicked
#        @return: False to ignore the click and True otherwise
#        """
#        print("clicked on", self[node_id])
#        return True
#
#    def OnDblClick(self, node_id):
#        """
#        Triggerd when a node is double-clicked.
#        @return: False to ignore the click and True otherwise
#        """
#        print("dblclicked on", self[node_id])
#        return True
#</pydoc>
#</pycode(py_graph)>
