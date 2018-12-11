from __future__ import print_function
# -----------------------------------------------------------------------
# Debugger command prompt with CustomViewers
# (c) Hex-Rays
#
import ida_idaapi
import ida_kernwin
import ida_lines
import ida_expr
import ida_dbg

# The viewer instance
dbgcmd = None

# -----------------------------------------------------------------------
class base_dbgcmd_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def update(self, ctx):
        if dbgcmd and ctx.widget == dbgcmd.GetWidget():
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

# -----------------------------------------------------------------------
class clear_dbgcmd_ah_t(base_dbgcmd_ah_t):
    def activate(self, ctx):
        dbgcmd.ResetOutput()

# -----------------------------------------------------------------------
class newcmd_dbgcmd_ah_t(base_dbgcmd_ah_t):
    def activate(self, ctx):
        dbgcmd.IssueCommand()

# -----------------------------------------------------------------------
class close_dbgcmd_ah_t(base_dbgcmd_ah_t):
    def activate(self, ctx):
        dbgcmd.Close()

# -----------------------------------------------------------------------
# Register actions (if needed)
ACTNAME_CLEAR = "dbgcmd:clear"
ACTNAME_NEWCMD = "dbgcmd:newcmd"
ACTNAME_CLOSE = "dbgcmd:close"
ida_kernwin.register_action(
    ida_kernwin.action_desc_t(
        ACTNAME_CLEAR, "Clear", clear_dbgcmd_ah_t(), "x"))
ida_kernwin.register_action(
    ida_kernwin.action_desc_t(
        ACTNAME_NEWCMD, "New command", newcmd_dbgcmd_ah_t(), "Insert"))
ida_kernwin.register_action(
    ida_kernwin.action_desc_t(
        ACTNAME_CLOSE, "Close", close_dbgcmd_ah_t(), "Escape"))

# -----------------------------------------------------------------------
class dbgcmd_t(ida_kernwin.simplecustviewer_t):
    def Create(self):
        # Form the title
        title = "Debugger command window"
        # Create the customview
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False
        self.last_cmd   = ""
        self.ResetOutput()
        return True

    def IssueCommand(self):
        s = ida_kernwin.ask_str(self.last_cmd, 0, "Please enter a debugger command")
        if not s:
            return

        # Save last command
        self.last_cmd = s

        # Add it using a different color
        self.AddLine("debugger>" + ida_lines.COLSTR(s, ida_lines.SCOLOR_VOIDOP))

        ok, out = ida_dbg.send_dbg_command(s)
        if ok:
            for line in out.split("\n"):
                self.AddLine(ida_lines.COLSTR(line, ida_lines.SCOLOR_LIBNAME))
        else:
            self.AddLine(
                ida_lines.COLSTR(
                    "Debugger is not active or does not export ida_dbg.send_dbg_command() (%s)" % out,
                    ida_lines.SCOLOR_ERROR))
        self.Refresh()

    def ResetOutput(self):
        self.ClearLines()
        self.AddLine(ida_lines.COLSTR("Please press INS to enter command; X to clear output", ida_lines.SCOLOR_AUTOCMT))
        self.Refresh()


# -----------------------------------------------------------------------
def show_win():
    x = dbgcmd_t()
    if not x.Create():
        print("Failed to create debugger command line!")
        return None
    x.Show()

    # Attach actions to this widget's popup menu
    widget = x.GetWidget()
    ida_kernwin.attach_action_to_popup(widget, None, ACTNAME_CLEAR)
    ida_kernwin.attach_action_to_popup(widget, None, ACTNAME_NEWCMD)
    ida_kernwin.attach_action_to_popup(widget, None, ACTNAME_CLOSE)
    return x

if dbgcmd is not None:
    dbgcmd.Close()
    dbgcmd = None

dbgcmd = show_win()
