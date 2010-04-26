#---------------------------------------------------------------------
# This script demonstrates the usage of hotkeys.
#
# Note: Hotkeys only work with the GUI version of IDA and not in
#       text mode.
#
# Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#---------------------------------------------------------------------
import idaapi

def foo():
 print "Hotkey activated!"

# IDA binds hotkeys to IDC functions so a trampoline IDC function
# must be created
idaapi.CompileLine('static key_2() { RunPythonStatement("foo()"); }')
# Add the hotkey
AddHotkey("2", 'key_2')

# Press 2 to activate foo()

# The hotkey can be removed with
# DelHotkey('2')

