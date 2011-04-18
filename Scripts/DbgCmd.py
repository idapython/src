# -----------------------------------------------------------------------
# Debugger command prompt with CustomViewers
# (c) Hex-Rays
#
import idaapi
import idc
from idaapi import simplecustviewer_t

def SendDbgCommand(cmd):
    """Sends a command to the debugger and returns the output string.
    An exception will be raised if the debugger is not running or the current debugger does not export
    the 'SendDbgCommand' IDC command.
    """
    s = Eval('SendDbgCommand("%s");' % cmd)
    if s.startswith("IDC_FAILURE"):
        raise Exception, "Debugger command is available only when the debugger is active!"
    return s

# -----------------------------------------------------------------------
class dbgcmd_t(simplecustviewer_t):
    def Create(self):
        # Form the title
        title = "Debugger command window"
        # Create the customview
        if not simplecustviewer_t.Create(self, title):
            return False
        self.last_cmd   = ""
        self.menu_clear = self.AddPopupMenu("Clear")
        self.menu_cmd   = self.AddPopupMenu("New command")

        self.ResetOutput()
        return True

    def IssueCommand(self):
        s = idaapi.askstr(0, self.last_cmd, "Please enter a debugger command")
        if not s:
            return

        # Save last command
        self.last_cmd = s

        # Add it using a different color
        self.AddLine("debugger>" + idaapi.COLSTR(s, idaapi.SCOLOR_VOIDOP))

        try:
            r = SendDbgCommand(s).split("\n")
            for s in r:
                self.AddLine(idaapi.COLSTR(s, idaapi.SCOLOR_LIBNAME))
        except:
            self.AddLine(idaapi.COLSTR("Debugger is not active or does not export SendDbgCommand()", idaapi.SCOLOR_ERROR))
        self.Refresh()

    def ResetOutput(self):
        self.ClearLines()
        self.AddLine(idaapi.COLSTR("Please press INS to enter command; X to clear output", idaapi.SCOLOR_AUTOCMT))
        self.Refresh()

    def OnKeydown(self, vkey, shift):
        # ESCAPE?
        if vkey == 27:
            self.Close()
        # VK_INSERT
        elif vkey == 45:
            self.IssueCommand()
        elif vkey == ord('X'):
            self.ResetOutput()
        else:
            return False
        return True

    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_clear:
            self.ResetOutput()
        elif menu_id == self.menu_cmd:
            self.IssueCommand()
        else:
            # Unhandled
            return False
        return True

# -----------------------------------------------------------------------
def show_win():
    x = dbgcmd_t()
    if not x.Create():
        print "Failed to create debugger command line!"
        return None
    x.Show()
    return x

try:
    # created already?
    dbgcmd
    dbgcmd.Close()
    del dbgcmd
except:
    pass

dbgcmd = show_win()
if not dbgcmd:
    del dbgcmd

