from __future__ import print_function
#---------------------------------------------------------------------
# This script demonstrates the usage of hotkeys, using an alternative API.
# See also:
#   add_hotkey.py
#   actions.py
#
# Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#---------------------------------------------------------------------

import ida_expr
import ida_kernwin

def say_hi():
    print("Hotkey activated!")

# IDA binds hotkeys to IDC functions so a trampoline IDC function must be created
ida_expr.compile_idc_text('static key_2() { RunPythonStatement("say_hi()"); }')

# Add the hotkey
ida_kernwin.add_idc_hotkey("2", 'key_2')

# Press 2 to activate foo()

# The hotkey can be removed with
# ida_kernwin.del_idc_hotkey('2')

