"""
summary: enumerate file imports

description:
  Using the API to enumerate file imports.
"""

import ida_nalt

nimps = ida_nalt.get_import_module_qty()

print("Found %d import(s)..." % nimps)

for i in range(nimps):
    name = ida_nalt.get_import_module_name(i)
    if not name:
        print("Failed to get import module name for #%d" % i)
        name = "<unnamed>"

    print("Walking imports for module %s" % name)
    def imp_cb(ea, name, ordinal):
        if not name:
            print("%08x: ordinal #%d" % (ea, ordinal))
        else:
            print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
    ida_nalt.enum_import_names(i, imp_cb)

print("All done...")
