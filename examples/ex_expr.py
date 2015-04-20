# -----------------------------------------------------------------------
# This is an example illustrating how to extend IDC from Python
# (c) Hex-Rays
#
from idaapi import set_idc_func_ex

#<pycode(ex_expr)>
def py_power(n, e):
    return n ** e

ok = set_idc_func_ex("pow", py_power, (idaapi.VT_LONG, idaapi.VT_LONG), 0)
if ok:
    print("Now the pow() will be present IDC!")
else:
    print("Failed to register pow() IDC function")
#</pycode(ex_expr)>
