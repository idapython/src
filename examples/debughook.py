#---------------------------------------------------------------------
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Original Author: Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#
# Maintained By: IDAPython Team
#
#---------------------------------------------------------------------
from idaapi import *

class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))
        return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        return 0

    def dbg_library_unload(self, pid, tid, ea, info):
        print("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))
        return 0

    def dbg_process_detach(self, pid, tid, ea):
        print("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))
        return 0

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        print "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base)

    def dbg_bpt(self, tid, ea):
        print "Break point at 0x%x pid=%d" % (ea, tid)
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.
        return 0

    def dbg_suspend_process(self):
        print "Process suspended"

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        print("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
            pid, tid, ea, exc_code & idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
        # return values:
        #   -1 - to display an exception warning dialog
        #        if the process is suspended.
        #   0  - to never display an exception warning dialog.
        #   1  - to always display an exception warning dialog.
        return 0

    def dbg_trace(self, tid, ea):
        print("Trace tid=%d ea=0x%x" % (tid, ea))
        return 0

    def dbg_step_into(self):
        print("Step into")
        return self.dbg_step_over()

#    def dbg_run_to(self, tid):
#        print "Runto: tid=%d" % tid
#        idaapi.continue_process()

    def dbg_step_over(self):
        eip = GetRegValue("EIP")
        print("0x%x %s" % (eip, GetDisasm(eip)))

        self.steps += 1
        if self.steps >= 5:
            request_exit_process()
        else:
            request_step_over()
        return 0

# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
except:
    pass

# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

# Stop at the entry point
ep = GetLongPrm(INF_START_IP)
request_run_to(ep)

# Step one instruction
request_step_over()

# Start debugging
run_requests()
