# -----------------------------------------------------------------------
#<pycode(py_kernwin_choose2)>
class Choose2(object):
    """
    Choose2 wrapper class.

    Some constants are defined in this class. Please refer to kernwin.hpp for more information.
    """

    CH_MODAL        = 0x01
    """Modal chooser"""

    CH_MULTI        = 0x02
    """Allow multi selection"""

    CH_MULTI_EDIT   = 0x04
    CH_NOBTNS       = 0x08
    CH_ATTRS        = 0x10
    CH_NOIDB        = 0x20
    """use the chooser even without an open database, same as x0=-2"""
    CH_UTF8         = 0x40
    """string encoding is utf-8"""

    CH_BUILTIN_MASK = 0xF80000

    # column flags (are specified in the widths array)
    CHCOL_PLAIN  =  0x00000000
    CHCOL_PATH   =  0x00010000
    CHCOL_HEX    =  0x00020000
    CHCOL_DEC    =  0x00030000
    CHCOL_FORMAT =  0x00070000


    def __init__(self, title, cols, flags=0, popup_names=None,
                 icon=-1, x1=-1, y1=-1, x2=-1, y2=-1, deflt=-1,
                 embedded=False, width=None, height=None):
        """
        Constructs a chooser window.
        @param title: The chooser title
        @param cols: a list of colums; each list item is a list of two items
            example: [ ["Address", 10 | Choose2.CHCOL_HEX], ["Name", 30 | Choose2.CHCOL_PLAIN] ]
        @param flags: One of CH_XXXX constants
        @param deflt: Default starting item
        @param popup_names: list of new captions to replace this list ["Insert", "Delete", "Edit", "Refresh"]
        @param icon: Icon index (the icon should exist in ida resources or an index to a custom loaded icon)
        @param x1, y1, x2, y2: The default location
        @param embedded: Create as embedded chooser
        @param width: Embedded chooser width
        @param height: Embedded chooser height
        """
        self.title = title
        self.flags = flags
        self.cols = cols
        self.deflt = deflt
        self.popup_names = popup_names
        self.icon = icon
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2
        self.embedded = embedded
        if embedded:
	        self.x1 = width
	        self.y1 = height


    def Embedded(self):
        """
        Creates an embedded chooser (as opposed to Show())
        @return: Returns 1 on success
        """
        return _ida_kernwin.choose2_create(self, True)


    def GetEmbSelection(self):
        """
        Returns the selection associated with an embedded chooser

        @return:
            - None if chooser is not embedded
            - A list with selection indices (0-based)
        """
        return _ida_kernwin.choose2_get_embedded_selection(self)


    def Show(self, modal=False):
        """
        Activates or creates a chooser window
        @param modal: Display as modal dialog
        @return: For modal choosers it will return the selected item index (0-based) or -1 if no selection
        """
        if modal:
            self.flags |= Choose2.CH_MODAL

            # Disable the timeout
            old = _ida_idaapi.set_script_timeout(0)
            n = _ida_kernwin.choose2_create(self, False)
            _ida_idaapi.set_script_timeout(old)

            # Delete the modal chooser instance
            self.Close()

            return n
        else:
            self.flags &= ~Choose2.CH_MODAL
            return _ida_kernwin.choose2_create(self, False)


    def Activate(self):
        """Activates a visible chooser"""
        return _ida_kernwin.choose2_activate(self)


    def Refresh(self):
        """Causes the refresh callback to trigger"""
        return _ida_kernwin.choose2_refresh(self)


    def Close(self):
        """Closes the chooser"""
        return _ida_kernwin.choose2_close(self)


    def AddCommand(self,
                   caption,
                   flags = _ida_kernwin.CHOOSER_POPUP_MENU,
                   menu_index = -1,
                   icon = -1,
				   emb=None):
        """
        Deprecated: Use
          - register_action()
          - attach_action_to_menu()
          - attach_action_to_popup()
        """
        # Use the 'emb' as a sentinel. It will be passed the correct value from the EmbeddedChooserControl
        if self.embedded and ((emb is None) or (emb != 2002)):
            raise RuntimeError("Please add a command through EmbeddedChooserControl.AddCommand()")
        return _ida_kernwin.choose2_add_command(self, caption, flags, menu_index, icon)

    #
    # Implement these methods in the subclass:
    #
#<pydoc>
#    def OnClose(self):
#        """
#        Called when the window is being closed.
#        This callback is mandatory.
#        @return: nothing
#        """
#        pass
#
#    def OnGetLine(self, n):
#        """Called when the chooser window requires lines.
#        This callback is mandatory.
#        @param n: Line number (0-based)
#        @return: The user should return a list with ncols elements.
#            example: a list [col1, col2, col3, ...] describing the n-th line
#        """
#        return ["col1 val", "col2 val"]
#
#    def OnGetSize(self):
#        """Returns the element count.
#        This callback is mandatory.
#        @return: Number of elements
#        """
#        return len(self.the_list)
#
#    def OnEditLine(self, n):
#        """
#        Called when an item is being edited.
#        @param n: Line number (0-based)
#        @return: Nothing
#        """
#        pass
#
#    def OnInsertLine(self):
#        """
#        Called when 'Insert' is selected either via the hotkey or popup menu.
#        @return: Nothing
#        """
#        pass
#
#    def OnSelectLine(self, n):
#        """
#        Called when a line is selected and then Ok or double click was pressed
#        @param n: Line number (0-based)
#        """
#        pass
#
#    def OnSelectionChange(self, sel_list):
#        """
#        Called when the selection changes
#        @param sel_list: A list of selected item indices
#        """
#        pass
#
#    def OnDeleteLine(self, n):
#        """
#        Called when a line is about to be deleted
#        @param n: Line number (0-based)
#        """
#        return self.n
#
#    def OnRefresh(self, n):
#        """
#        Triggered when the 'Refresh' is called from the popup menu item.
#
#        @param n: The currently selected line (0-based) at the time of the refresh call
#        @return: Return the new selected line
#        """
#        return self.n
#
#    def OnRefreshed(self):
#        """
#        Triggered when a refresh happens (for example due to column sorting)
#        """
#
#    def OnCommand(self, n, cmd_id):
#        """Return int ; check add_chooser_command()"""
#        return 0
#
#    def OnGetIcon(self, n):
#        """
#        Return icon number for a given item (or -1 if no icon is avail)
#        @param n: Line number (0-based)
#        """
#        return -1
#
#    def OnGetLineAttr(self, n):
#        """
#        Return list [bgcolor, flags=CHITEM_XXXX] or None; check chooser_item_attrs_t
#        @param n: Line number (0-based)
#        """
#        return [0x0, CHITEM_BOLD]
#</pydoc>
#</pycode(py_kernwin_choose2)>
