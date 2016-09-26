# -----------------------------------------------------------------------
#<pycode(py_kernwin_custview)>
class simplecustviewer_t(object):
    """The base class for implementing simple custom viewers"""
    def __init__(self):
        self.__this = None

    def __del__(self):
        """Destructor. It also frees the associated C++ object"""
        try:
            _ida_kernwin.pyscv_delete(self.__this)
        except:
            pass

    @staticmethod
    def __make_sl_arg(line, fgcolor=None, bgcolor=None):
        return line if (fgcolor is None and bgcolor is None) else (line, fgcolor, bgcolor)

    def Create(self, title):
        """
        Creates the custom view. This should be the first method called after instantiation

        @param title: The title of the view
        @return: Boolean whether it succeeds or fails. It may fail if a window with the same title is already open.
                 In this case better close existing windows
        """
        self.title = title
        self.__this = _ida_kernwin.pyscv_init(self, title)
        return True if self.__this else False

    def Close(self):
        """
        Destroys the view.
        One has to call Create() afterwards.
        Show() can be called and it will call Create() internally.
        @return: Boolean
        """
        return _ida_kernwin.pyscv_close(self.__this)

    def Show(self):
        """
        Shows an already created view. It the view was close, then it will call Create() for you
        @return: Boolean
        """
        return _ida_kernwin.pyscv_show(self.__this)

    def Refresh(self):
        return _ida_kernwin.pyscv_refresh(self.__this)

    def RefreshCurrent(self):
        """Refreshes the current line only"""
        return _ida_kernwin.pyscv_refresh_current(self.__this)

    def Count(self):
        """Returns the number of lines in the view"""
        return _ida_kernwin.pyscv_count(self.__this)

    def GetSelection(self):
        """
        Returns the selected area or None
        @return:
            - tuple(x1, y1, x2, y2)
            - None if no selection
        """
        return _ida_kernwin.pyscv_get_selection(self.__this)

    def ClearLines(self):
        """Clears all the lines"""
        _ida_kernwin.pyscv_clear_lines(self.__this)

    def AddLine(self, line, fgcolor=None, bgcolor=None):
        """
        Adds a colored line to the view
        @return: Boolean
        """
        return _ida_kernwin.pyscv_add_line(self.__this, self.__make_sl_arg(line, fgcolor, bgcolor))

    def InsertLine(self, lineno, line, fgcolor=None, bgcolor=None):
        """
        Inserts a line in the given position
        @return: Boolean
        """
        return _ida_kernwin.pyscv_insert_line(self.__this, lineno, self.__make_sl_arg(line, fgcolor, bgcolor))

    def EditLine(self, lineno, line, fgcolor=None, bgcolor=None):
        """
        Edits an existing line.
        @return: Boolean
        """
        return _ida_kernwin.pyscv_edit_line(self.__this, lineno, self.__make_sl_arg(line, fgcolor, bgcolor))

    def PatchLine(self, lineno, offs, value):
        """Patches an existing line character at the given offset. This is a low level function. You must know what you're doing"""
        return _ida_kernwin.pyscv_patch_line(self.__this, lineno, offs, value)

    def DelLine(self, lineno):
        """
        Deletes an existing line
        @return: Boolean
        """
        return _ida_kernwin.pyscv_del_line(self.__this, lineno)

    def GetLine(self, lineno):
        """
        Returns a line
        @param lineno: The line number
        @return:
            Returns a tuple (colored_line, fgcolor, bgcolor) or None
        """
        return _ida_kernwin.pyscv_get_line(self.__this, lineno)

    def GetCurrentWord(self, mouse = 0):
        """
        Returns the current word
        @param mouse: Use mouse position or cursor position
        @return: None if failed or a String containing the current word at mouse or cursor
        """
        return _ida_kernwin.pyscv_get_current_word(self.__this, mouse)

    def GetCurrentLine(self, mouse = 0, notags = 0):
        """
        Returns the current line.
        @param mouse: Current line at mouse pos
        @param notags: If True then tag_remove() will be called before returning the line
        @return: Returns the current line (colored or uncolored) or None on failure
        """
        return _ida_kernwin.pyscv_get_current_line(self.__this, mouse, notags)

    def GetPos(self, mouse = 0):
        """
        Returns the current cursor or mouse position.
        @param mouse: return mouse position
        @return: Returns a tuple (lineno, x, y)
        """
        return _ida_kernwin.pyscv_get_pos(self.__this, mouse)

    def GetLineNo(self, mouse = 0):
        """Calls GetPos() and returns the current line number or -1 on failure"""
        r = self.GetPos(mouse)
        return -1 if not r else r[0]

    def Jump(self, lineno, x=0, y=0):
        return _ida_kernwin.pyscv_jumpto(self.__this, lineno, x, y)

    def AddPopupMenu(self, title, hotkey=""):
        """
        Adds a popup menu item, and get its ID (for use in the OnPopupMenu() handler)
        @param title: The name of the menu item
        @param hotkey: Hotkey of the item or just empty
        @return: Returns the id of the registered popup menu item
        """
        return _ida_kernwin.pyscv_add_popup_menu(self.__this, title, hotkey)

    def ClearPopupMenu(self):
        """
        Clears all previously installed popup menu items.
        Use this function if you're generating menu items on the fly (in the OnPopup() callback),
        and before adding new items
        """
        _ida_kernwin.pyscv_clear_popup_menu(self.__this)

    def IsFocused(self):
        """Returns True if the current view is the focused view"""
        return _ida_kernwin.pyscv_is_focused(self.__this)

    def GetTForm(self):
        """
        Return the TForm hosting this view.

        @return: The TForm that hosts this view, or None.
        """
        return _ida_kernwin.pyscv_get_tform(self.__this)

    def GetTCustomControl(self):
        """
        Return the TCustomControl underlying this view.

        @return: The TCustomControl underlying this view, or None.
        """
        return _ida_kernwin.pyscv_get_tcustom_control(self.__this)



    # Here are all the supported events
#<pydoc>
#    def OnClick(self, shift):
#        """
#        User clicked in the view
#        @param shift: Shift flag
#        @return: Boolean. True if you handled the event
#        """
#        print "OnClick, shift=%d" % shift
#        return True
#
#    def OnDblClick(self, shift):
#        """
#        User dbl-clicked in the view
#        @param shift: Shift flag
#        @return: Boolean. True if you handled the event
#        """
#        print "OnDblClick, shift=%d" % shift
#        return True
#
#    def OnCursorPosChanged(self):
#        """
#        Cursor position changed.
#        @return: Nothing
#        """
#        print "OnCurposChanged"
#
#    def OnClose(self):
#        """
#        The view is closing. Use this event to cleanup.
#        @return: Nothing
#        """
#        print "OnClose"
#
#    def OnKeydown(self, vkey, shift):
#        """
#        User pressed a key
#        @param vkey: Virtual key code
#        @param shift: Shift flag
#        @return: Boolean. True if you handled the event
#        """
#        print "OnKeydown, vk=%d shift=%d" % (vkey, shift)
#        return False
#
#    def OnPopup(self):
#        """
#        Context menu popup is about to be shown. Create items dynamically if you wish
#        @return: Boolean. True if you handled the event
#        """
#        print "OnPopup"
#
#    def OnHint(self, lineno):
#        """
#        Hint requested for the given line number.
#        @param lineno: The line number (zero based)
#        @return:
#            - tuple(number of important lines, hint string)
#            - None: if no hint available
#        """
#        return (1, "OnHint, line=%d" % lineno)
#
#    def OnPopupMenu(self, menu_id):
#        """
#        A context (or popup) menu item was executed.
#        @param menu_id: ID previously registered with add_popup_menu()
#        @return: Boolean
#        """
#        print "OnPopupMenu, menu_id=" % menu_id
#        return True
#</pydoc>
#</pycode(py_kernwin_custview)>
