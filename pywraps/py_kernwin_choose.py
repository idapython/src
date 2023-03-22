#--------------------------------------------------------------------------
#<pycode(py_kernwin_choose)>
import _ida_kernwin

class Choose(object):
    """
    Chooser wrapper class.

    Some constants are defined in this class.
    Please refer to kernwin.hpp for more information.
    """

    CH_MODAL        = _ida_kernwin.CH_MODAL
    """Modal chooser"""

    CH_MULTI        = _ida_kernwin.CH_MULTI
    """
    Allow multi selection.
    Refer the description of the OnInsertLine(), OnDeleteLine(),
    OnEditLine(), OnSelectLine(), OnRefresh(), OnSelectionChange() to
    see a difference between single and multi selection callbacks.
    """

    CH_NOBTNS       = _ida_kernwin.CH_NOBTNS

    CH_ATTRS        = _ida_kernwin.CH_ATTRS

    CH_NOIDB        = _ida_kernwin.CH_NOIDB
    """use the chooser even without an open database, same as x0=-2"""

    CH_FORCE_DEFAULT = _ida_kernwin.CH_FORCE_DEFAULT
    """
    If a non-modal chooser was already open, change selection to the given
    default one
    """

    CH_CAN_INS      = _ida_kernwin.CH_CAN_INS
    """allow to insert new items"""

    CH_CAN_DEL      = _ida_kernwin.CH_CAN_DEL
    """allow to delete existing item(s)"""

    CH_CAN_EDIT     = _ida_kernwin.CH_CAN_EDIT
    """allow to edit existing item(s)"""

    CH_CAN_REFRESH  = _ida_kernwin.CH_CAN_REFRESH
    """allow to refresh chooser"""

    CH_QFLT         =  _ida_kernwin.CH_QFLT
    """open with quick filter enabled and focused"""

    CH_QFTYP_SHIFT  = _ida_kernwin.CH_QFTYP_SHIFT
    CH_QFTYP_DEFAULT     = _ida_kernwin.CH_QFTYP_DEFAULT
    CH_QFTYP_NORMAL      = _ida_kernwin.CH_QFTYP_NORMAL
    CH_QFTYP_WHOLE_WORDS = _ida_kernwin.CH_QFTYP_WHOLE_WORDS
    CH_QFTYP_REGEX       = _ida_kernwin.CH_QFTYP_REGEX
    CH_QFTYP_FUZZY       = _ida_kernwin.CH_QFTYP_FUZZY
    CH_QFTYP_MASK        = _ida_kernwin.CH_QFTYP_MASK

    CH_NO_STATUS_BAR = _ida_kernwin.CH_NO_STATUS_BAR
    """don't show a status bar"""
    CH_RESTORE       = _ida_kernwin.CH_RESTORE
    """restore floating position if present (equivalent of WOPN_RESTORE) (GUI version only)"""

    CH_RENAME_IS_EDIT = _ida_kernwin.CH_RENAME_IS_EDIT
    """triggering a 'edit/rename' (i.e., F2 shortcut) on a cell,
       should call the edit() callback for the corresponding row."""

    CH_BUILTIN_SHIFT = _ida_kernwin.CH_BUILTIN_SHIFT
    CH_BUILTIN_MASK = _ida_kernwin.CH_BUILTIN_MASK

    """The chooser can provide a dirtree_t, meaning a tree-like structure
       can be provided to the user (instead of a flat table)"""
    CH_HAS_DIRTREE = _ida_kernwin.CH_HAS_DIRTREE

    """The chooser can be used in a diffing/merging workflow"""
    CH_HAS_DIFF = _ida_kernwin.CH_HAS_DIFF

    # column flags (are specified in the widths array)
    CHCOL_PLAIN     = _ida_kernwin.CHCOL_PLAIN
    CHCOL_PATH      = _ida_kernwin.CHCOL_PATH
    CHCOL_HEX       = _ida_kernwin.CHCOL_HEX
    CHCOL_DEC       = _ida_kernwin.CHCOL_DEC
    CHCOL_EA        = _ida_kernwin.CHCOL_EA
    CHCOL_FNAME     = _ida_kernwin.CHCOL_FNAME
    CHCOL_FORMAT    = _ida_kernwin.CHCOL_FORMAT
    CHCOL_DEFHIDDEN = _ida_kernwin.CHCOL_DEFHIDDEN
    CHCOL_DRAGHINT  = _ida_kernwin.CHCOL_DRAGHINT
    CHCOL_INODENAME = _ida_kernwin.CHCOL_INODENAME

    # special values of the chooser index
    NO_SELECTION   = -1
    """there is no selected item"""
    EMPTY_CHOOSER  = -2
    """the chooser is initialized"""
    ALREADY_EXISTS = -3
    """the non-modal chooser with the same data is already open"""
    NO_ATTR        = -4
    """some mandatory attribute is missing"""

    # return value of ins(), del(), edit(), enter(), refresh() callbacks
    NOTHING_CHANGED   = 0
    ALL_CHANGED       = 1
    SELECTION_CHANGED = 2

    class UI_Hooks_Trampoline(UI_Hooks):
        def __init__(self, v):
            UI_Hooks.__init__(self)
            self.hook()
            import weakref
            self.v = weakref.ref(v)

        def populating_widget_popup(self, widget, popup_handle):
            chooser = self.v()
            if widget == chooser.GetWidget() and \
               hasattr(chooser, "OnPopup") and \
               callable(getattr(chooser, "OnPopup")):
                chooser.OnPopup(widget, popup_handle)

    def __init__(self, title, cols, flags = 0, popup_names = None,
                 icon=-1, x1=-1, y1=-1, x2=-1, y2=-1,
                 deflt = None,
                 embedded = False, width = None, height = None,
                 forbidden_cb = 0, flags2 = 0):
        """
        Constructs a chooser window.
        @param title: The chooser title
        @param cols: a list of colums; each list item is a list of two items
            example: [ ["Address", 10 | Choose.CHCOL_HEX],
                       ["Name",    30 | Choose.CHCOL_PLAIN] ]
        @param flags: One of CH_XXXX constants
        @param flags2: One of CH2_XXXX constants
        @param deflt: The index of the default item (0-based) for single
            selection choosers or the list of indexes for multi selection
            chooser
        @param popup_names: List of new captions to replace this list
            ["Insert", "Delete", "Edit", "Refresh"]
        @param icon: Icon index (the icon should exist in ida resources or
            an index to a custom loaded icon)
        @param x1, y1, x2, y2: The default location (for txt-version)
        @param embedded: Create as embedded chooser
        @param width: Embedded chooser width
        @param height: Embedded chooser height
        @param forbidden_cb: Explicitly forbidden callbacks
        """
        self.title = title
        self.flags = flags
        self.flags2 = flags2
        self.cols = cols
        if deflt == None:
          deflt = 0 if (flags & Choose.CH_MULTI) == 0 else [0]
        self.deflt = deflt
        self.popup_names = popup_names
        self.icon = icon
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2
        self.embedded = embedded
        self.width = width
        self.height = height
        self.forbidden_cb = forbidden_cb
        self.ui_hooks_trampoline = None # set on Show
        def _qccb(ctx, cmd_id):
            for idx in ctx.chooser_selection:
                self.OnCommand(idx, cmd_id)
        self._quick_commands = quick_widget_commands_t(_qccb)


    def Embedded(self, create_chobj=False):
        """
        Creates an embedded chooser (as opposed to Show())
        @return: Returns 0 on success or NO_ATTR
        """
        if not self.embedded:
          return Choose.NO_ATTR
        if create_chobj:
            return _ida_kernwin.choose_create_embedded_chobj(self)
        else:
            return _ida_kernwin.choose_choose(self)


    def GetEmbSelection(self):
        """
        Deprecated. For embedded choosers, the selection is
        available through 'Form.EmbeddedChooserControl.selection'
        """
        return None


    def Show(self, modal=False):
        """
        Activates or creates a chooser window
        @param modal: Display as modal dialog
        @return: For all choosers it will return NO_ATTR if some mandatory
                 attribute is missing. The mandatory attributes are: flags,
                 title, cols, OnGetSize(), OnGetLine();
                 For modal choosers it will return the selected item index (0-based),
                 or NO_SELECTION if no selection,
                 or EMPTY_CHOOSER if the OnRefresh() callback returns EMPTY_CHOOSER;
                 For non-modal choosers it will return 0
                 or ALREADY_EXISTS if the chooser was already open and is active now;
        """
        if self.embedded:
          return Choose.NO_ATTR
        # it will be deleted and unhooked in py_choose_t::closed()
        self.ui_hooks_trampoline = self.UI_Hooks_Trampoline(self)
        if modal:
            self.flags |= Choose.CH_MODAL

            # Disable the timeout
            with disabled_script_timeout_t():
                n = _ida_kernwin.choose_choose(self)

            # Delete the modal chooser instance
            self.Close()

            return n
        else:
            self.flags &= ~Choose.CH_MODAL
            return _ida_kernwin.choose_choose(self)


    def Activate(self):
        """Activates a visible chooser"""
        return _ida_kernwin.choose_activate(self)


    def Refresh(self):
        """Causes the refresh callback to trigger"""
        return _ida_kernwin.choose_refresh(self)


    def Close(self):
        """Closes the chooser"""
        if not self.embedded:
            _ida_kernwin.choose_close(self)

    def GetWidget(self):
        """
        Return the TWidget underlying this view.

        @return: The TWidget underlying this view, or None.
        """
        return _ida_kernwin.choose_get_widget(self)

    def adjust_last_item(self, n):
        """
        Helper for OnDeleteLine() and OnRefresh() callbacks.
        They can be finished by the following line:
        return [Choose.ALL_CHANGED] + self.adjust_last_item(n)
        @param: line number of the remaining select item
        @return: list of selected lines numbers (one element or empty)
        """
        cnt = self.OnGetSize()
        if cnt == 0:
            return []
        # take in account deleting of the last item(s)
        if n >= cnt:
            n = cnt - 1
        return [n]

    def AddCommand(self,
                   caption,
                   flags = _ida_kernwin.CHOOSER_POPUP_MENU,
                   menu_index = -1,
                   icon = -1,
                   emb=None,
                   shortcut=None):
        return self._quick_commands.add(
            caption=caption,
            flags=flags,
            menu_index=menu_index,
            icon=icon,
            emb=emb,
            shortcut=shortcut)

    def OnPopup(self, widget, popup_handle):
        self._quick_commands.populate_popup(widget, popup_handle)

    def OnInit(self):
        """
        Initialize the chooser and populate it.

        This callback is optional
        """
        pass

    def OnGetSize(self):
        """
        Get the number of elements in the chooser.

        This callback is mandatory

        @return the number of elements
        """
        pass

    def OnGetLine(self, n):
        """
        Get data for an element

        This callback is mandatory

        @param n the index to fetch data for
        @return a list of strings
        """
        pass

    def OnGetIcon(self, n):
        """
        Get an icon to associate with the first cell of an element

        @param n index of the element
        @return an icon ID
        """
        pass

    def OnGetLineAttr(self, n):
        """
        Get attributes for an element

        @param n index of the element
        @return a tuple (color, flags)
        """
        pass

    def OnInsertLine(self, sel):
        """
        User asked to insert an element

        @param sel the current selection
        @return a tuple (changed, selection)
        """
        pass

    def OnDeleteLine(self, sel):
        """
        User deleted an element

        @param sel the current selection
        @return a tuple (changed, selection)
        """
        pass

    def OnEditLine(self, sel):
        """
        User asked to edit an element.

        @param sel the current selection
        @return a tuple (changed, selection)
        """
        pass

    def OnSelectLine(self, sel):
        """
        User pressed the enter key, or double-clicked a selection

        @param sel the current selection
        @return a tuple (changed, selection)
        """
        pass

    def OnSelectionChange(self, sel):
        """
        Selection changed

        @param sel the new selection
        """
        pass

    def OnRefresh(self, sel):
        """
        The chooser needs to be refreshed.
        It returns the new positions of the selected items.

        @param sel the current selection
        @return a tuple (changed, selection)
        """
        pass

    def OnClose(self):
        """
        The chooser window is closed.
        """
        pass

    def OnGetEA(self, n):
        """
        Get the address of an element

        When this function returns valid addresses:
          * If any column has the `CHCOL_FNAME` flag, rows will
            be colored according to the attributes of the functions
            who own those addresses (extern, library function,
            Lumina, ... - similar to what the "Functions" widget does)
          * When a selection is present and the user presses `<Enter>`
            (`<Shift+Enter>` if the chooser is modal), IDA will jump
            to that address (through jumpto())
        @param n element number (0-based)
        @return the effective address, ida_idaapi.BADADDR if the element has no address
        """
        pass

    def OnGetDirTree(self):
        """
        Get the dirtree_t that will be used to present a tree-like
        structure to the user (see CH_HAS_DIRTREE)

        @return the dirtree_t, or None
        """
        pass

    def OnIndexToInode(self, n):
        """
        Map an element index to a dirtree_t inode

        This callback is mandatory if CH_HAS_DIRTREE is specified

        @param n index of the element
        @return the inode number
        """
        pass

    def OnIndexToDiffpos(self, n):
        """
        Map an element index to a diffpos_t

        This callback is mandatory if CH_HAS_DIFF is specified

        @param n index of the element
        @return the diffpos
        """
        pass

    def OnLazyLoadDir(self, path):
        """
        Callback for lazy-loaded, dirtree-based choosers;
        the function will be called when a folder is expanded and it has
        not been loaded before. The implementation should use the
        given dirtree's link() or mkdir() methods to add the folder contents.

        @param path an absolute dirtree path to the directory that is being expanded
        @return success
        """
        pass

#</pycode(py_kernwin_choose)>
