# -----------------------------------------------------------------------
# This is an example illustrating how to enumerate imports
# (c) Hex-Rays
#
import idaapi

def imp_cb(ea, name, ord):
    if not name:
        print "%08x: ord#%d" % (ea, ord)
    else:
        print "%08x: %s (ord#%d)" % (ea, name, ord)
    # True -> Continue enumeration
    # False -> Stop enumeration
    return True

nimps = idaapi.get_import_module_qty()

print "Found %d import(s)..." % nimps

for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
        print "Failed to get import module name for #%d" % i
        continue

    print "Walking-> %s" % name
    idaapi.enum_import_names(i, imp_cb)

print "All done..."