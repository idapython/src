# -----------------------------------------------------------------------
# This is an example illustrating how to enumerate all addresses
# that refer to all imported functions in a given module
#
# (c) Hex-Rays
#

import idaapi
import idc
import idautils
import re

# -----------------------------------------------------------------------
def find_imported_funcs(dllname):
    def imp_cb(ea, name, ord):
        if not name:
            name = ''
        imports.append([ea, name, ord])
        return True

    imports = []
    nimps = idaapi.get_import_module_qty()
    for i in xrange(0, nimps):
        name = idaapi.get_import_module_name(i)
        if re.match(dllname, name, re.IGNORECASE) is None:
            continue
        idaapi.enum_import_names(i, imp_cb)

    return imports


# -----------------------------------------------------------------------
def find_import_ref(dllname):
    imports = find_imported_funcs(dllname)
    R = dict()
    for i, (ea, name,_) in enumerate(imports):
        #print "%x -> %s" % (ea, name)
        for xref in idautils.XrefsTo(ea):
            # check if referrer is a thunk
            ea = xref.frm
            f = idaapi.get_func(ea)
            if f and (f.flags & idaapi.FUNC_THUNK) != 0:
                imports.append([f.startEA, idaapi.get_func_name(f.startEA), 0])
                #print "\t%x %s: from a thunk, parent added %x" % (ea, name, f.startEA)
                continue

            # save results
            if not R.has_key(i):
                R[i] = []

            R[i].append(ea)

    return (imports, R)

# -----------------------------------------------------------------------
def main():
    dllname = idc.AskStr('kernel32', "Enter module name")
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