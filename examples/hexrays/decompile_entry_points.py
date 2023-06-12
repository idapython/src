"""
summary: automatic decompilation of functions

description:
  Attempts to load a decompiler plugin corresponding to the current
  architecture (and address size) right after auto-analysis is performed,
  and then tries to decompile the function at the first entrypoint.

  It is particularly suited for use with the '-S' flag, for example:
  idat -Ldecompile.log -Sdecompile_entry_points.py -c file
"""

import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry
import ida_kernwin

# because the -S script runs very early, we need to load the decompiler
# manually if we want to use it
def init_hexrays():
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: "hexrays",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
    }
    cpu = ida_idp.ph.id
    decompiler = ALL_DECOMPILERS.get(cpu, None)
    if not decompiler:
        print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)
        return False
    if ida_ida.inf_is_64bit():
        if cpu == ida_idp.PLFM_386:
            decompiler = "hexx64"
        else:
            decompiler += "64"
    if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
        return True
    else:
        print('Couldn\'t load or initialize decompiler: "%s"' % decompiler)
        return False


def decompile_func(ea, outfile):
    ida_kernwin.msg("Decompiling at: %X..." % ea)
    cf = ida_hexrays.decompile(ea)
    if cf:
        ida_kernwin.msg("OK\n")
        outfile.write(str(cf) + "\n")
    else:
        ida_kernwin.msg("failed!\n")
        outfile.write("decompilation failure at %X!\n" % ea)


def main():
    print("Waiting for autoanalysis...")
    ida_auto.auto_wait()
    if init_hexrays():
        eqty = ida_entry.get_entry_qty()
        if eqty:
            idbpath = idc.get_idb_path()
            cpath = idbpath[:-4] + ".c"
            with open(cpath, "w") as outfile:
                print("writing results to '%s'..." % cpath)
                for i in range(eqty):
                    ea = ida_entry.get_entry(ida_entry.get_entry_ordinal(i))
                    decompile_func(ea, outfile)
        else:
            print("No known entrypoint. Cannot decompile.")
    if ida_kernwin.cvar.batch:
        print("All done, exiting.")
        ida_pro.qexit(0)

main()
