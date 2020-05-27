from __future__ import print_function
#
# This example tries to load a decompiler plugin corresponding to the current
# architecture (and address size) right after auto-analysis is performed,
# and then tries to decompile the function at the first entrypoint.
#
# It is particularly suited for use with the '-S' flag.
#

import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry

ida_auto.auto_wait()
ALL_DECOMPILERS = {
    ida_idp.PLFM_386 : ("hexrays", "hexx64"),
    ida_idp.PLFM_ARM : ("hexarm",  "hexarm64"),
    ida_idp.PLFM_PPC : ("hexppc",  "hexppc64"),
    ida_idp.PLFM_MIPS: ("hexmips", "hexmips64"),
}
pair = ALL_DECOMPILERS.get(ida_idp.ph.id, None)
if pair:
    decompiler = pair[1 if ida_ida.cvar.inf.is_64bit() else 0]
    if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
        eqty = ida_entry.get_entry_qty()
        if eqty:
            ea = ida_entry.get_entry(ida_entry.get_entry_ordinal(0))
            print("Decompiling at: %X" % ea)
            cf = ida_hexrays.decompile(ea)
            if cf:
                print(cf)
            else:
                print("Decompilation failed")
        else:
            print("No known entrypoint. Cannot decompile.")
    else:
        print("Couldn't load or initialize decompiler: \"%s\"" % decompiler)
else:
    print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
