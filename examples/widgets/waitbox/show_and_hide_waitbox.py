
#
# A simple example showing how to use:
#  ida_kernwin.show_wait_box
#  ida_kernwin.hide_wait_box
#  ida_kernwin.replace_wait_box
#

import time
import random

import ida_kernwin
import ida_hexrays
import ida_funcs

import idautils

perform_decompilation=False

# Note: this try/except block below is just there to
# let us (at Hex-Rays) test this script in various
# situations.
try:
    perform_decompilation = under_test__perform_decompilation
except:
    pass


step_sleep = 0.5
ida_kernwin.show_wait_box("Processing")
try:
    all_eas = list(idautils.Functions())
    neas = len(all_eas)
    for i, ea in enumerate(all_eas):
        if ida_kernwin.user_cancelled():
            break
        ida_kernwin.replace_wait_box("Processing; step %d/%d" % (i+1, neas))

        if perform_decompilation:
            try:
                ida_hexrays.decompile(ida_funcs.get_func(ea))
            except ida_hexrays.DecompilationFailure as df:
                print("Decompilation failure: %s" % df)

        time.sleep(step_sleep * random.random())
finally:
    ida_kernwin.hide_wait_box()


