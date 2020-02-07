#--------------------------------------------------------------------------
#<pycode(py_kernwin_choose)>
class Choose(object):
    """
    Chooser wrapper class.

    Some constants are defined in this class.
    Please refer to kernwin.hpp for more information.
    """

    CH_MODAL        = 0x01
    """Modal chooser"""

    CH_MULTI        = 0x04
    """
    Allow multi selection.
    Refer the description of the OnInsertLine(), OnDeleteLine(),
    OnEditLine(), OnSelectLine(), OnRefresh(), OnSelectionChange() to
    see a difference between single and multi selection callbacks.
    """

    CH_NOBTNS       = 0x10

    CH_ATTRS        = 0x20

    CH_NOIDB        = 0x40
    """use the chooser even without an open database, same as x0=-2"""

    CH_FORCE_DEFAULT = 0x80
    """
    If a non-modal chooser was already open, change selection to the given
    default one
    """

    CH_CAN_INS      = 0x000100
    """allow to insert new items"""

    CH_CAN_DEL      = 0x000200
    """allow to delete existing item(s)"""

    CH_CAN_EDIT     = 0x000400
    """allow to edit existing item(s)"""

    CH_CAN_REFRESH  = 0x000800
    """allow to refresh chooser"""

    CH_QFLT         =  0x1000
    """open with quick filter enabled and focused"""

    CH_QFTYP_SHIFT  = 13
    CH_QFTYP_DEFAULT     = 0 << CH_QFTYP_SHIFT
    CH_QFTYP_NORMAL      = 1 << CH_QFTYP_SHIFT
    CH_QFTYP_WHOLE_WORDS = 2 << CH_QFTYP_SHIFT
    CH_QFTYP_REGEX       = 3 << CH_QFTYP_SHIFT
    CH_QFTYP_FUZZY       = 4 << CH_QFTYP_SHIFT
    CH_QFTYP_MASK        = 0x7 << CH_QFTYP_SHIFT

    CH_NO_STATUS_BAR = 0x00010000
    """don't show a status bar"""
    CH_RESTORE       = 0x00020000
    """restore floating position if present (equivalent of WOPN_RESTORE) (GUI version only)"""

    CH_BUILTIN_SHIFT = 19
    CH_BUILTIN_MASK = 0x1F << CH_BUILTIN_SHIFT

    # column flags (are specified in the widths array)
    CHCOL_PLAIN  =  0x00000000
    CHCOL_PATH   =  0x00010000
    CHCOL_HEX    =  0x00020000
    CHCOL_DEC    =  0x00030000
    CHCOL_FORMAT =  0x00070000

    # special values of the chooser index
    NO_SELECTION   = -1
    """there is no selected item"""
    EMPTY_CHOOSER  = -4
    """the chooser is initialized"""
    ALREADY_EXISTS = -5
    """the non-modal chooser with the same data is already open"""
    NO_ATTR        = -6
    """some mandatory attribute is missing"""

    # return value of ins(), del(), edit(), enter(), refresh() callbacks
    NOTHING_CHANGED   = 0
    ALL_CHANGED       = 1
    SELECTION_CHANGED = 2

    # to construct `forbidden_cb`
    CHOOSE_HAVE_INIT    = 0x0001
    CHOOSE_HAVE_GETICON = 0x0002
    CHOOSE_HAVE_GETATTR = 0x0004
    CHOOSE_HAVE_INS     = 0x0008
    CHOOSE_HAVE_DEL     = 0x0010
    CHOOSE_HAVE_EDIT    = 0x0020
    CHOOSE_HAVE_ENTER   = 0x0040
    CHOOSE_HAVE_REFRESH = 0x0080
    CHOOSE_HAVE_SELECT  = 0x0100
    CHOOSE_HAVE_ONCLOSE = 0x0200

    class UI_Hooks_Trampoline(UI_Hooks):
        def __init__(self, v):
            UI_Hooks.__init__(self)
            self.hook()
            import weakref
            self.v = weakref.ref(v)

        def populating_widget_popup(self, form, popup_handle):
            chooser = self.v()
            if form == chooser.GetWidget() and \
               hasattr(chooser, "OnPopup") and \
               callable(getattr(chooser, "OnPopup")):
                chooser.OnPopup(form, popup_handle)

    def __init__(self, title, cols, flags = 0, popup_names = None,
                 icon=-1, x1=-1, y1=-1, x2=-1, y2=-1,
                 deflt = None,
                 embedded = False, width = None, height = None,
                 forbidden_cb = 0):
        """
        Constructs a chooser window.
        @param title: The chooser title
        @param cols: a list of colums; each list item is a list of two items
            example: [ ["Address", 10 | Choose.CHCOL_HEX],
                       ["Name",    30 | Choose.CHCOL_PLAIN] ]
        @param flags: One of CH_XXXX constants
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


    def Embedded(self):
        """
        Creates an embedded chooser (as opposed to Show())
        @return: Returns 0 on success or NO_ATTR
        """
        if not self.embedded:
          return Choose.NO_ATTR
        return _ida_kernwin.choose_create(self)


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
            old = _ida_idaapi.set_script_timeout(0)
            n = _ida_kernwin.choose_create(self)
            _ida_idaapi.set_script_timeout(old)

            # Delete the modal chooser instance
            self.Close()

            return n
        else:
            self.flags &= ~Choose.CH_MODAL
            return _ida_kernwin.choose_create(self)


    def Activate(self):
        """Activates a visible chooser"""
        return _ida_kernwin.choose_activate(self)


    def Refresh(self):
        """Causes the refresh callback to trigger"""
        return _ida_kernwin.choose_refresh(self)


    def Close(self):
        """Closes the chooser"""
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
        cnt = self.OnGetSize();
        if cnt == 0:
            return []
        # take in account deleting of the last item(s)
        if n >= cnt:
            n = cnt - 1
        return [n]
#</pycode(py_kernwin_choose)>
