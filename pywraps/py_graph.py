#<pycode(py_graph)>
class GraphViewer(object):
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

    def AddNode(self, obj):
        """Creates a node associated with the given object and returns the node id"""
        id = len(self._nodes)
        self._nodes.append(obj)
        return id

    def AddEdge(self, src_node, dest_node):
        """Creates an edge between two given node ids"""
        self._edges.append( (src_node, dest_node) )

    def Clear(self):
        """Clears all the nodes and edges"""
        self._nodes = []
        self._edges = []


    def __iter__(self):
        return (self._nodes[index] for index in xrange(0, len(self._nodes)))


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
        _idaapi.pyg_close(self)

    def Refresh(self):
        """
        Refreshes the graph. This causes the OnRefresh() to be called
        """
        _idaapi.pyg_refresh(self)

    def Show(self):
        """
        Shows an existing graph or creates a new one

        @return: Boolean
        """
        if self._close_open:
            frm = _idaapi.find_tform(self._title)
            if frm:
                _idaapi.close_tform(frm, 0)
        return _idaapi.pyg_show(self)

    def Select(self, node_id):
        """Selects a node on the graph"""
        _idaapi.pyg_select_node(self, node_id)

    def AddCommand(self, title, hotkey):
        """
        Adds a menu command to the graph. Call this command after the graph is shown (with Show()).
        Once a command is added, a command id is returned. The commands are handled inside the OnCommand() handler

        @return: 0 on failure or the command id
        """
        return _idaapi.pyg_add_command(self, title, hotkey)

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
#        print "Activated...."
#
#    def OnDeactivate(self):
#        """Triggered when the graph window loses the focus
#        @return: None
#        """
#        print "Deactivated...."
#
#    def OnSelect(self, node_id):
#        """
#        Triggered when a node is being selected
#        @return: Return True to allow the node to be selected or False to disallow node selection change
#        """
#        # allow selection change
#        return True
#
#    def OnHint(self, node_id):
#        """
#        Triggered when the graph viewer wants to retrieve hint text associated with a given node
#
#        @return: None if no hint is avail or a string designating the hint
#        """
#        return "hint for " + str(node_id)
#
#    def OnClose(self):
#        """Triggered when the graph viewer window is being closed
#        @return: None
#        """
#        print "Closing......."
#
#    def OnClick(self, node_id):
#        """
#        Triggered when a node is clicked
#        @return: False to ignore the click and True otherwise
#        """
#        print "clicked on", self[node_id]
#        return True
#
#    def OnDblClick(self, node_id):
#        """
#        Triggerd when a node is double-clicked.
#        @return: False to ignore the click and True otherwise
#        """
#        print "dblclicked on", self[node_id]
#        return True
#
#    def OnCommand(self, cmd_id):
#        """
#        Triggered when a menu command is selected through the menu or its hotkey
#        @return: None
#        """
#        print "command:", cmd_id
#</pydoc>
#</pycode(py_graph)>