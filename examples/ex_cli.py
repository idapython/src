# -----------------------------------------------------------------------
# This is an example illustrating how to implement a CLI
# (c) Hex-Rays
#
from idaapi import NW_OPENIDB, NW_CLOSEIDB, NW_TERMIDA, NW_REMOVE, COLSTR, cli_t

#<pycode(ex_cli_ex1)>
class mycli_t(cli_t):
    flags = 0
    sname = "pycli"
    lname = "Python CLI"
    hint  = "pycli hint"

    def OnExecuteLine(self, line):
        """
        The user pressed Enter. The CLI is free to execute the line immediately or ask for more lines.

        This callback is mandatory.

        @param line: typed line(s)
        @return Boolean: True-executed line, False-ask for more lines
        """
        print "OnExecute:", line
        return True

    def OnKeydown(self, line, x, sellen, vkey, shift):
        """
        A keyboard key has been pressed
        This is a generic callback and the CLI is free to do whatever it wants.

        This callback is optional.

        @param line: current input line
        @param x: current x coordinate of the cursor
        @param sellen: current selection length (usually 0)
        @param vkey: virtual key code. if the key has been handled, it should be returned as zero
        @param shift: shift state

        @return:
            None - Nothing was changed
            tuple(line, x, sellen, vkey): if either of the input line or the x coordinate or the selection length has been modified.
            It is possible to return a tuple with None elements to preserve old values. Example: tuple(new_line, None, None, None) or tuple(new_line)
        """
        print "Onkeydown: line=%s x=%d sellen=%d vkey=%d shift=%d" % (line, x, sellen, vkey, shift)
        return None

    def OnCompleteLine(self, prefix, n, line, prefix_start):
        """
        The user pressed Tab. Find a completion number N for prefix PREFIX

        This callback is optional.

        @param prefix: Line prefix at prefix_start (string)
        @param n: completion number (int)
        @param line: the current line (string)
        @param prefix_start: the index where PREFIX starts in LINE (int)

        @return: None if no completion could be generated otherwise a String with the completion suggestion
        """
        print "OnCompleteLine: prefix=%s n=%d line=%s prefix_start=%d" % (prefix, n, line, prefix_start)
        return None
#</pycode(ex_cli_ex1)>


# -----------------------------------------------------------------------
def nw_handler(code, old=0):
    if code == NW_OPENIDB:
        print "nw_handler(): installing CLI"
        mycli.register()
    elif code == NW_CLOSEIDB:
        print "nw_handler(): removing CLI"
        mycli.unregister()
    elif code == NW_TERMIDA:
        print "nw_handler(): uninstalled nw handler"
        idaapi.notify_when(NW_TERMIDA | NW_OPENIDB | NW_CLOSEIDB | NW_REMOVE, nw_handler)

# -----------------------------------------------------------------------

# Already installed?
try:
    mycli
    # remove previous CLI
    mycli.unregister()
    del mycli
    # remove previous handler
    nw_handler(NW_TERMIDA)
except:
    pass
finally:
    mycli = mycli_t()

# register CLI
if mycli.register():
    print "CLI installed"
    # install new handler
    idaapi.notify_when(NW_TERMIDA | NW_OPENIDB | NW_CLOSEIDB, nw_handler)
else:
    del mycli
    print "Failed to install CLI"

