
class GraphViewer(ida_kernwin.CustomIDAMemo):

    def OnGetText(self, node_id):
        """
        Triggered when the graph viewer wants the text and color for a given node.
        This callback is triggered one time for a given node (the value will be cached and used later without callin Python).
        When you call refresh then again this callback will be called for each node.

        This callback is mandatory.

        @return: Return a string to describe the node text or return a tuple (node_text, node_color) to describe bot text and color
        """
        return str(self[node_id])

    def OnActivate(self):
        """
        Triggered when the graph window gets the focus
        @return: None
        """
        print("Activated....")

    def OnDeactivate(self):
        """Triggered when the graph window loses the focus
        @return: None
        """
        print("Deactivated....")

    def OnHint(self, node_id):
        """
        Triggered when the graph viewer wants to retrieve hint text associated with a given node

        @return: None if no hint is avail or a string designating the hint
        """
        return "hint for " + str(node_id)

    def OnEdgeHint(self, src, dst):
        """
        Triggered when the graph viewer wants to retrieve hint text associated with a edge

        @return: None if no hint is avail or a string designating the hint
        """
        return "hint for edge %d -> %d" % (src, dst)

    def OnClose(self):
        """Triggered when the graph viewer window is being closed
        @return: None
        """
        print("Closing.......")

    def OnClick(self, node_id):
        """
        Triggered when a node is clicked
        @return: False to ignore the click and True otherwise
        """
        print("clicked on", self[node_id])
        return True

    def OnDblClick(self, node_id):
        """
        Triggerd when a node is double-clicked.
        @return: False to ignore the click and True otherwise
        """
        print("dblclicked on", self[node_id])
        return True
