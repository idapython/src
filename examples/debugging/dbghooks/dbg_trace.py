"""
summary: using the low-level tracing hook

description:
  This script demonstrates using the low-level tracing hook
  (ida_dbg.DBG_Hooks.dbg_trace). It can be run like so:

       ida[t].exe -B -Sdbg_trace.py -Ltrace.log file.exe
"""

import time

import ida_dbg
import ida_ida
import ida_pro
import ida_ua
from ida_allins import NN_callni, NN_call, NN_callfi
from ida_lines import generate_disasm_line, GENDSM_FORCE_CODE, GENDSM_REMOVE_TAGS

# Note: this try/except block below is just there to
# let us (at Hex-Rays) test this script in various
# situations.
try:
    import idc
    print(idc.ARGV[1])
    under_test = bool(idc.ARGV[1])
except:
    under_test = False

class TraceHook(ida_dbg.DBG_Hooks):
    def __init__(self):
        ida_dbg.DBG_Hooks.__init__(self)
        self.traces = 0
        self.epReached = False

    def _log(self, msg):
        print(">>> %s" % msg)

    def dbg_trace(self, tid, ea):
        # Log all traced addresses
        if ea < ida_ida.inf_get_min_ea() or ea > ida_ida.inf_get_max_ea():
            raise Exception(
                "Received a trace callback for an address outside this database!"
            )

        self._log("trace %08X" % ea)
        self.traces += 1
        insn = ida_ua.insn_t()
        insnlen = ida_ua.decode_insn(insn, ea)
        # log disassembly and ESP for call instructions
        if insnlen > 0 and insn.itype in [NN_callni, NN_call, NN_callfi]:
            self._log(
                "call insn: %s"
                % generate_disasm_line(ea, GENDSM_FORCE_CODE | GENDSM_REMOVE_TAGS)
            )
            self._log("ESP=%08X" % ida_dbg.get_reg_val("ESP"))

        return 1

    def dbg_run_to(self, pid, tid=0, ea=0):
        # this hook is called once execution reaches temporary breakpoint set by run_to(ep) below
        if not self.epReached:
            ida_dbg.refresh_debugger_memory()
            self._log("reached entry point at 0x%X" % ida_dbg.get_reg_val("EIP"))
            self._log("current step trace options: %x" % ida_dbg.get_step_trace_options())
            self.epReached = True

        # enable step tracing (single-step the program and generate dbg_trace events)
        ida_dbg.request_enable_step_trace(1)
        # change options to only "over debugger segments" (i.e. library functions will be traced)
        ida_dbg.request_set_step_trace_options(ida_dbg.ST_OVER_DEBUG_SEG)
        ida_dbg.request_continue_process()
        ida_dbg.run_requests()

    def dbg_process_exit(self, pid, tid, ea, code):
        self._log("process exited with %d" % code)
        self._log("traced %d instructions" % self.traces)
        return 0


def do_trace(then_quit_ida=True):
    debugHook = TraceHook()
    debugHook.hook()

    # Start tracing when entry point is hit
    ep = ida_ida.inf_get_start_ip()
    ida_dbg.enable_step_trace(1)
    ida_dbg.set_step_trace_options(ida_dbg.ST_OVER_DEBUG_SEG | ida_dbg.ST_OVER_LIB_FUNC)
    print("Running to %x" % ep)
    ida_dbg.run_to(ep)

    while ida_dbg.get_process_state() != 0:
        ida_dbg.wait_for_next_event(1, 0)

    if not debugHook.epReached:
        raise Exception("Entry point wasn't reached!")

    if not debugHook.unhook():
        raise Exception("Error uninstalling hooks!")

    del debugHook

    if then_quit_ida:
        # we're done; exit IDA
        ida_pro.qexit(0)


# load the debugger module depending on the file type
if ida_ida.inf_get_filetype() == ida_ida.f_PE:
    ida_dbg.load_debugger("win32", 0)
elif ida_ida.inf_get_filetype() == ida_ida.f_ELF:
    ida_dbg.load_debugger("linux", 0)
elif ida_ida.inf_get_filetype() == ida_ida.f_MACHO:
    ida_dbg.load_debugger("mac", 0)
if not under_test:
    do_trace()
