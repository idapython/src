"""
summary: programmatically drive a debugging session

description:
  Start a debugging session, step through the first five
  instructions. Each instruction is disassembled after
  execution.
"""

import ida_dbg
import ida_ida
import ida_lines

class MyDbgHook(ida_dbg.DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def __init__(self):
        ida_dbg.DBG_Hooks.__init__(self) # important
        self.steps = 0

    def log(self, msg):
        print(">>> %s" % msg)

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self.log("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))

    def dbg_process_exit(self, pid, tid, ea, code):
        self.log("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))

    def dbg_library_unload(self, pid, tid, ea, info):
        self.log("Library unloaded: pid=%d tid=%d ea=0x%x info=%s" % (pid, tid, ea, info))

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self.log("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))

    def dbg_process_detach(self, pid, tid, ea):
        self.log("Process detached, pid=%d tid=%d ea=0x%x" % (pid, tid, ea))

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        self.log("Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base))

    def dbg_bpt(self, tid, ea):
        self.log("Break point at 0x%x pid=%d" % (ea, tid))
        # return values:
        #   -1 - to display a breakpoint warning dialog
        #        if the process is suspended.
        #    0 - to never display a breakpoint warning dialog.
        #    1 - to always display a breakpoint warning dialog.
        return 0

    def dbg_suspend_process(self):
        self.log("Process suspended")

    def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
        self.log("Exception: pid=%d tid=%d ea=0x%x exc_code=0x%x can_continue=%d exc_ea=0x%x exc_info=%s" % (
            pid, tid, ea, exc_code & ida_idaapi.BADADDR, exc_can_cont, exc_ea, exc_info))
        # return values:
        #   -1 - to display an exception warning dialog
        #        if the process is suspended.
        #   0  - to never display an exception warning dialog.
        #   1  - to always display an exception warning dialog.
        return 0

    def dbg_trace(self, tid, ea):
        self.log("Trace tid=%d ea=0x%x" % (tid, ea))
        # return values:
        #   1  - do not log this trace event;
        #   0  - log it
        return 0

    def dbg_step_into(self):
        self.log("Step into")
        self.dbg_step_over()

    def dbg_run_to(self, pid, tid=0, ea=0):
        self.log("Runto: tid=%d, ea=%x" % (tid, ea))
        ida_dbg.request_step_over()

    def dbg_step_over(self):
        eip = ida_dbg.get_reg_val("EIP")
        disasm = ida_lines.tag_remove(
            ida_lines.generate_disasm_line(
                eip))
        self.log("Step over: EIP=0x%x, disassembly=%s" % (eip, disasm))

        self.steps += 1
        if self.steps >= 5:
            ida_dbg.request_exit_process()
        else:
            ida_dbg.request_step_over()


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

ep = ida_ida.inf_get_start_ip()
if ida_dbg.request_run_to(ep): # Request stop at entry point
    ida_dbg.run_requests()     # Launch process
else:
    print("Impossible to prepare debugger requests. Is a debugger selected?")
