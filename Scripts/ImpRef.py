from __future__ import print_function
# -----------------------------------------------------------------------
# This is an example illustrating how to enumerate all addresses
# that refer to all imported functions in a given module
#
# (c) Hex-Rays
#
import re

import ida_kernwin
import ida_nalt
import ida_funcs

import idautils

# -----------------------------------------------------------------------
def find_imported_funcs(dllname):
    def imp_cb(ea, name, ord):
        if not name:
            name = ''
        imports.append([ea, name, ord])
        return True

    imports = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(0, nimps):
        name = ida_nalt.get_import_module_name(i)
        if re.match(dllname, name, re.IGNORECASE) is None:
            continue
        ida_nalt.enum_import_names(i, imp_cb)

    return imports


# -----------------------------------------------------------------------
def find_import_ref(dllname):
    imports = find_imported_funcs(dllname)
    R = dict()
    for i, (ea, name,_) in enumerate(imports):
        #print("%x -> %s" % (ea, name))
        for xref in idautils.XrefsTo(ea):
            # check if referrer is a thunk
            ea = xref.frm
            f = ida_funcs.get_func(ea)
            if f and (f.flags & ida_funcs.FUNC_THUNK) != 0:
                imports.append([f.start_ea, ida_funcs.get_func_name(f.start_ea), 0])
                #print("\t%x %s: from a thunk, parent added %x" % (ea, name, f.start_ea))
                continue

            # save results
            if i not in R:
                R[i] = []

            R[i].append(ea)

    return (imports, R)

# -----------------------------------------------------------------------
def main():
    dllname = ida_kernwin.ask_str('kernel32', 0, "Enter module name")
    if not dllname:
        print("Cancelled")
        return

    imports, R = find_import_ref(dllname)
    for k, v in R.items():
        print(imports[k][1])
        for ea in v:
            print("\t%x" % ea)

# -----------------------------------------------------------------------
main()
