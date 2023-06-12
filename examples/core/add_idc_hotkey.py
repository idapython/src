"""
summary: triggering bits of code by pressing a shortcut (older version)

description:
  This is a somewhat ancient way of registering actions & binding
  shortcuts. It's still here for reference, but "fresher" alternatives
  should be preferred.

keywords: actions

see_also: actions, add_hotkey
"""

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

