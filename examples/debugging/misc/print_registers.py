"""
summary: print all registers, for all threads

description: iterate over the list of threads in the program being
             debugged, and dump all registers contents

  To use this example:

    * run `ida64` on test program `simple_appcall_linux64`, or
      `ida` on test program `simple_appcall_linux32`, and wait for
      auto-analysis to finish
    * put a breakpoint somewhere in the code
    * select the 'linux debugger' (either local, or remote)
    * start debugging
    * Press Alt+Shift+C at the breakpoint
"""
import ida_idd
import ida_dbg

def log(msg):
    print(">>> %s" % msg)

class print_registers_ah_t():
    def activate(self, ctx):
        log("=== registers ===")
        dbg = ida_idd.get_dbg()
        for tidx in range(ida_dbg.get_thread_qty()):
            tid = ida_dbg.getn_thread(tidx)
            log("  Thread #%d" % tid)
            regvals = ida_dbg.get_reg_vals(tid)
            for ridx, rv in enumerate(regvals):
                rinfo = dbg.regs(ridx)
                rval = rv.pyval(rinfo.dtype)
                if isinstance(rval, int):
                    rval = "0x%x" % rval
                log("    %s: %s" % (rinfo.name, rval))
        log("=== end of registers  ===")

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

ACTION_NAME = "example:print_registers"
ACTION_LABEL = "Print registers"
ACTION_SHORTCUT = "Alt+Shift+C"
ACTION_HELP = "Press %s to print the registers" % ACTION_SHORTCUT

if ida_kernwin.register_action(ida_kernwin.action_desc_t(
        ACTION_NAME,
        ACTION_LABEL,
        print_registers_ah_t(),
        ACTION_SHORTCUT)):
    print("Registered action \"%s\". %s" % (ACTION_LABEL, ACTION_HELP))

