
#<pycode(py_view_base)>
class CustomIDAMemo(object):
    def Refresh(self):
        """
        Refreshes the graph. This causes the OnRefresh() to be called
        """
        _idaapi.pygc_refresh(self)

    def GetCurrentRendererType(self):
        return _idaapi.pygc_get_current_renderer_type(self)

    def SetCurrentRendererType(self, rtype):
        """
        Set the current view's renderer.

        @param rtype: The renderer type. Should be one of the idaapi.TCCRT_* values.
        """
        _idaapi.pygc_set_current_renderer_type(self, rtype)

    def SetNodeInfo(self, node_index, node_info, flags):
        """
        Set the properties for the given node.

        Example usage (set second nodes's bg color to red):
          inst = ...
          p = idaapi.node_info_t()
          p.bg_color = 0x00ff0000
          inst.SetNodeInfo(1, p, idaapi.NIF_BG_COLOR)

        @param node_index: The node index.
        @param node_info: An idaapi.node_info_t instance.
        @param flags: An OR'ed value of NIF_* values.
        """
        _idaapi.pygc_set_node_info(self, node_index, node_info, flags)

    def SetNodesInfos(self, values):
        """
        Set the properties for the given nodes.

        Example usage (set first three nodes's bg color to purple):
          inst = ...
          p = idaapi.node_info_t()
          p.bg_color = 0x00ff00ff
          inst.SetNodesInfos({0 : p, 1 : p, 2 : p})

        @param values: A dictionary of 'int -> node_info_t' objects.
        """
        _idaapi.pygc_set_nodes_infos(self, values)

    def GetNodeInfo(self, node):
        """
        Get the properties for the given node.

        @param node: The index of the node.
        @return: A tuple (bg_color, frame_color, ea, text), or None.
        """
        return _idaapi.pygc_get_node_info(self, node)

    def DelNodesInfos(self, *nodes):
        """
        Delete the properties for the given node(s).

        @param nodes: A list of node IDs
        """
        return _idaapi.pygc_del_nodes_infos(self, nodes)

    def CreateGroups(self, groups_infos):
        """
        Send a request to modify the graph by creating a
        (set of) group(s), and perform an animation.

        Each object in the 'groups_infos' list must be of the format:
        {
          "nodes" : [<int>, <int>, <int>, ...] # The list of nodes to group
          "text" : <string>                    # The synthetic text for that group
        }

        @param groups_infos: A list of objects that describe those groups.
        @return: A [<int>, <int>, ...] list of group nodes, or None (failure).
        """
        return _idaapi.pygc_create_groups(self, groups_infos)

    def DeleteGroups(self, groups, new_current = -1):
        """
        Send a request to delete the specified groups in the graph,
        and perform an animation.

        @param groups: A list of group node numbers.
        @param new_current: A node to focus on after the groups have been deleted
        @return: True on success, False otherwise.
        """
        return _idaapi.pygc_delete_groups(self, groups, new_current)

    def SetGroupsVisibility(self, groups, expand, new_current = -1):
        """
        Send a request to expand/collapse the specified groups in the graph,
        and perform an animation.

        @param groups: A list of group node numbers.
        @param expand: True to expand the group, False otherwise.
        @param new_current: A node to focus on after the groups have been expanded/collapsed.
        @return: True on success, False otherwise.
        """
        return _idaapi.pygc_set_groups_visibility(self, groups, expand, new_current)

    def GetTForm(self):
        """
        Return the TForm hosting this view.

        @return: The TForm that hosts this view, or None.
        """
        return _idaapi.pycim_get_tform(self)

    def GetTCustomControl(self):
        """
        Return the TCustomControl underlying this view.

        @return: The TCustomControl underlying this view, or None.
        """
        return _idaapi.pycim_get_tcustom_control(self)


#</pycode(py_view_base)>
