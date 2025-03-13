"""
summary: add a custom command-line interpreter

description:
  Illustrates how one can add command-line interpreters to IDA

  This custom interpreter doesn't actually run any code; it's
  there as a 'getting started'.
  It provides an example tab completion support.

level: advanced
"""

# -----------------------------------------------------------------------
# This is an example illustrating how to implement a CLI
#
# A trivial example is also provided for tab completion. To try it,
# type "bon" in the input field, and then press <Tab> multiple times.
#
# (c) Hex-Rays

import ida_kernwin
import ida_idaapi
import traceback

class mycli_t(ida_kernwin.cli_t):
    flags = 0
    sname = "pycli"
    lname = "Python CLI"
    hint  = "pycli hint"

    def OnExecuteLine(self, line):
        print("OnExecute:", line)
        return True

    def OnKeydown(self, line, x, sellen, vkey, shift):
        print("Onkeydown: line=%s x=%d sellen=%d vkey=%d shift=%d" % (line, x, sellen, vkey, shift))
        return None

    completions = [
        "bonnie & clyde",
        "bonfire of the vanities",
        "bongiorno",
    ]

    def OnFindCompletions(self, line, x):
        """
        The user pressed Tab. Return a list of completions

        This callback is optional.

        @param line: the current line (string)
        @param x: the index where the cursor is (int)

        @return: None if no completion could be generated, otherwise a tuple:
            (completions : Sequence[str], hints : Sequence[str], docs: Sequence[str], 
              match_start: int, match_end: int)
        """
        try:
            print("OnFindCompletions: line=%s x=%d" % (line, x))
            # self.debug("__call__(line=%s, x=%s)", line, x)
            uline = line
            if line[x-3:x]=="bon":
                return (self.completions, [], [], x-3, x)
        except:
            print("OnFindCompletions got exception:\n%s", traceback.format_exc())
            pass

# -----------------------------------------------------------------------
def nw_handler(code, old=0):
    if code == ida_idaapi.NW_OPENIDB:
        print("nw_handler(): installing CLI")
        mycli.register()
    elif code == ida_idaapi.NW_CLOSEIDB:
        print("nw_handler(): removing CLI")
        mycli.unregister()
    elif code == ida_idaapi.NW_TERMIDA:
        print("nw_handler(): uninstalled nw handler")
        when = ida_idaapi.NW_TERMIDA | ida_idaapi.NW_OPENIDB | ida_idaapi.NW_CLOSEIDB | ida_idaapi.NW_REMOVE
        ida_idaapi.notify_when(when, nw_handler)

# -----------------------------------------------------------------------

# Already installed?
try:
    mycli
    # remove previous CLI
    mycli.unregister()
    del mycli
    # remove previous handler
    nw_handler(ida_idaapi.NW_TERMIDA)
except:
    pass
finally:
    mycli = mycli_t()

# register CLI
if mycli.register():
    print("CLI installed")
    # install new handler
    when = ida_idaapi.NW_TERMIDA | ida_idaapi.NW_OPENIDB | ida_idaapi.NW_CLOSEIDB
    ida_idaapi.notify_when(when, nw_handler)
else:
    del mycli
    print("Failed to install CLI")

