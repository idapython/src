from __future__ import print_function
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
 print("Hotkey activated!")

# IDA binds hotkeys to IDC functions so a trampoline IDC function
# must be created
idaapi.compile_idc_text('static key_2() { RunPythonStatement("foo()"); }')
# Add the hotkey
add_idc_hotkey("2", 'key_2')

# Press 2 to activate foo()

# The hotkey can be removed with
# del_idc_hotkey('2')

