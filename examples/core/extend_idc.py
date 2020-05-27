from __future__ import print_function
# -----------------------------------------------------------------------
# This is an example illustrating how to extend IDC from Python
# (c) Hex-Rays
#

import ida_expr

if ida_expr.add_idc_func(
        "pow",
        lambda n, e: n ** e,
        (ida_expr.VT_LONG, ida_expr.VT_LONG)):
    print("The pow() function is now available in IDC")
else:
    print("Failed to register pow() IDC function")
