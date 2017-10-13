# -----------------------------------------------------------------------
# This is an example illustrating how to extend IDC from Python
# (c) Hex-Rays
#
from idaapi import add_idc_func

def py_power(n, e):
    return n ** e

desc = ext_idcfunc_t
desc.name = "pow"
desc.func = py_power,
desc.args = (idaapi.VT_LONG, idaapi.VT_LONG),
desc.defvals = ()
desc.flags = 0
ok = add_idc_func(desc)
if ok:
    print("Now the pow() will be present IDC!")
else:
    print("Failed to register pow() IDC function")
