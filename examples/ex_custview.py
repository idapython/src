# -----------------------------------------------------------------------
# This is an example illustrating how to use customview in Python
# (c) Hex-Rays
#
import idaapi
import idc
from idaapi import simplecustview_t
#<pycode(py_custviewex1)>

# -----------------------------------------------------------------------
class mycv_t(simplecustview_t):
    def Create(self, sn=None):
        # Form the title
        title = "Simple custom view test"
        if sn:
            title += " %d" % sn
        # Create the customview
        if not simplecustview_t.Create(self, title):
            return False
        id = self.AddPopupMenu("Hello")
        for i in xrange(0, 100):
            self.AddLine("Line %d" % i)
        return True

    def OnClick(self, shift):
        """
        User clicked in the view
        @param shift: Shift flag
        @return Boolean. True if you handled the event
        """
        print "OnClick, shift=%d" % shift
        return True

    def OnDblClick(self, shift):
        """
        User dbl-clicked in the view
        @param shift: Shift flag
        @return Boolean. True if you handled the event
        """
        print "OnDblClick, shift=%d" % shift
        return True

    def OnCursorPosChanged(self):
        """
        Cursor position changed.
        @return Nothing
        """
        print "OnCurposChanged"

    def OnClose(self):
        """
        The view is closing. Use this event to cleanup.
        @return Nothing
        """
        print "OnClose " + self.title

    def OnKeydown(self, vkey, shift):
        """
        User pressed a key
        @param vkey: Virtual key code
        @param shift: Shift flag
        @return Boolean. True if you handled the event
        """
        print "OnKeydown, vk=%d shift=%d" % (vkey, shift)
        # ESCAPE?
        if vkey == 27:
            self.Close()
        elif vkey == 46:
            n = self.GetLineNo()
            self.DelLine(n)
            self.Refresh()
            print "Deleted line %d" % n
        # Goto?
        elif vkey == ord('G'):
            v = idc.AskLong(self.GetLineNo(), "Where to go?")
            if v:
                self.Jump(v, 0, 5)
        elif vkey == ord('R'):
            print "refreshing...."
            self.Refresh()
        elif vkey == ord('C'):
            print "refreshing current line..."
            self.RefreshCurrent()
        elif vkey == ord('A'):
            s = idc.AskStr("NewLine%d" % self.Count(), "Append new line")
            self.AddLine(s)
            self.Refresh()
        elif vkey == ord('X'):
            print "Clearing all lines"
            self.ClearLines()
            self.Refresh()
        elif vkey == ord('I'):
            n = self.GetLineNo()
            s = idc.AskStr("InsertedLine%d" % n, "Insert new line")
            self.InsertLine(n, s)
            self.Refresh()
        elif vkey == ord('E'):
            l = self.GetCurrentLine(notags=1)
            if not l:
                return False
            n = self.GetLineNo()
            print "curline=<%s>" % l
            l = l + idaapi.COLSTR("*", idaapi.SCOLOR_VOIDOP)
            self.EditLine(n, l)
            self.RefreshCurrent()
            print "Edited line %d" % n
        else:
            return False
        return True

    def OnPopup(self):
        """
        Context menu popup is about to be shown. Create items dynamically if you wish
        @return Boolean. True if you handled the event
        """
        print "OnPopup"

    def OnHint(self, lineno):
        """
        Hint requested for the given line number.
        @param lineno: The line number (zero based)
        @return:
            - string: a string containing the hint
            - None: if no hint available
        """
        return "OnHint, line=%d" % lineno

    def OnPopupMenu(self, menu_id):
        """
        A context (or popup) menu item was executed.
        @param menu_id: ID previously registered with add_popup_menu()
        @return: Boolean
        """
        print "OnPopupMenu, menu_id=%d" % menu_id
        return True

# -----------------------------------------------------------------------
try:
    # created already?
    mycv
    print "Already created, will close it..."
    mycv.Close()
    del mycv
except:
    pass

def show_win():
    x = mycv_t()
    if not x.Create():
        print "Failed to create!"
        return None
    x.Show()
    return x
mycv = show_win()
if not mycv:
    del mycv

def make_many(n):
    for i in xrange(1, n+1):
        t = mycv_t()
        if not t.Create(i):
            break
        t.Show()
    return i

#</pycode(py_custviewex1)>