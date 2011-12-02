# -----------------------------------------------------------------------
# Standalone and testing code
import sys
try:
    import pywraps
    pywraps_there = True
    print "Using pywraps"
except:
    pywraps_there = False
    print "Using IDAPython"

try:
    import _idaapi
    from idaapi import pyidc_opaque_object_t
except:
    print "Please run this script from inside IDA"
    sys.exit(0)

if pywraps_there:
    _idaapi.install_command_interpreter = pywraps.install_command_interpreter
    _idaapi.remove_command_interpreter = pywraps.remove_command_interpreter

# -----------------------------------------------------------------------
#<pycode(py_cli)>
class cli_t(pyidc_opaque_object_t):
    """
    cli_t wrapper class.

    This class allows you to implement your own command line interface handlers.
    """

    def __init__(self):
        self.__cli_idx = -1
        self.__clink__ = None


    def register(self, flags = 0, sname = None, lname = None, hint = None):
        """
        Registers the CLI.

        @param flags: Feature bits. No bits are defined yet, must be 0
        @param sname: Short name (displayed on the button)
        @param lname: Long name (displayed in the menu)
        @param hint:  Hint for the input line

        @return Boolean: True-Success, False-Failed
        """

        # Already registered?
        if self.__cli_idx >= 0:
            return True

        if sname is not None: self.sname = sname
        if lname is not None: self.lname = lname
        if hint is not None:  self.hint  = hint

        # Register
        self.__cli_idx = _idaapi.install_command_interpreter(self)
        return False if self.__cli_idx < 0 else True


    def unregister(self):
        """
        Unregisters the CLI (if it was registered)
        """
        if self.__cli_idx < 0:
            return False

        _idaapi.remove_command_interpreter(self.__cli_idx)
        self.__cli_idx = -1
        return True


    def __del__(self):
        self.unregister()

    #
    # Implement these methods in the subclass:
    #
#<pydoc>
#    def OnExecuteLine(self, line):
#        """
#        The user pressed Enter. The CLI is free to execute the line immediately or ask for more lines.
#
#        This callback is mandatory.
#
#        @param line: typed line(s)
#        @return Boolean: True-executed line, False-ask for more lines
#        """
#        return True
#
#    def OnKeydown(self, line, x, sellen, vkey, shift):
#        """
#        A keyboard key has been pressed
#        This is a generic callback and the CLI is free to do whatever it wants.
#
#        This callback is optional.
#
#        @param line: current input line
#        @param x: current x coordinate of the cursor
#        @param sellen: current selection length (usually 0)
#        @param vkey: virtual key code. if the key has been handled, it should be returned as zero
#        @param shift: shift state
#
#        @return:
#            None - Nothing was changed
#            tuple(line, x, sellen, vkey): if either of the input line or the x coordinate or the selection length has been modified.
#            It is possible to return a tuple with None elements to preserve old values. Example: tuple(new_line, None, None, None) or tuple(new_line)
#        """
#        return None
#
#    def OnCompleteLine(self, prefix, n, line, prefix_start):
#        """
#        The user pressed Tab. Find a completion number N for prefix PREFIX
#
#        This callback is optional.
#
#        @param prefix: Line prefix at prefix_start (string)
#        @param n: completion number (int)
#        @param line: the current line (string)
#        @param prefix_start: the index where PREFIX starts in LINE (int)
#
#        @return: None if no completion could be generated otherwise a String with the completion suggestion
#        """
#        return None
#</pydoc>

#</pycode(py_cli)>

# -----------------------------------------------------------------------
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
