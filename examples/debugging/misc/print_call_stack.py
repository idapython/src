"""
summary: print call stack (on Linux)

description: print the return addresses from the call stack at a breakpoint.
             (and print also the module and the debug name from debugger)

  To use this example:

    * run `ida64` on test program `simple_appcall_linux64`, or
      `ida` on test program `simple_appcall_linux32`, and wait for
      auto-analysis to finish
    * put a breakpoint where you want to see the call stack
    * select the 'linux debugger' (either local, or remote)
    * start debugging
    * Press Shift+C at the breakpoint
"""
import os
import ida_idaapi
import ida_idd
import ida_dbg
import ida_kernwin
import ida_name

def log(msg):
    print(">>> %s" % msg)

class print_call_stack_ah_t():
    def activate(self, ctx):
        log("=== start of call stack impression ===")
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()
        if ida_dbg.collect_stack_trace(tid, trace):
            for frame in trace:
                mi = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, mi):
                    module = os.path.basename(mi.name)
                    name = ida_name.get_nice_colored_name(
                    frame.callea,
                    ida_name.GNCN_NOCOLOR|ida_name.GNCN_NOLABEL|ida_name.GNCN_NOSEG|ida_name.GNCN_PREFDBG)
                    log("Return address: " + hex(frame.callea) + " from: " + module + " with debug name: " + name)
                else:
                    log("Return address: " + hex(frame.callea))
        log("===  end of call stack impression  ===")

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

ACTION_NAME = "example:print_call_stack"
ACTION_LABEL = "Print call stack"
ACTION_SHORTCUT = "Shift+C"
ACTION_HELP = "Press %s to dump the call stack" % ACTION_SHORTCUT

if ida_kernwin.register_action(ida_kernwin.action_desc_t(
        ACTION_NAME,
        ACTION_LABEL,
        print_call_stack_ah_t(),
        ACTION_SHORTCUT)):
    print("Registered action \"%s\". %s" % (ACTION_LABEL, ACTION_HELP))

