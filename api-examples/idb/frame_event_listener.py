"""
summary: log various frame events.

description:
  hooks to be notified about frame IDP events, and 
  dump their information to the "Output" window.
"""
import inspect
import ida_idp
import ida_ua

class frame_logger_hooks_t(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        self.inhibit_log = 0
    
    def _format_value(self, v):
        return str(v)
    
    def _log(self, msg=None):
        if self.inhibit_log <= 0:
            if msg:
                print(f'>>> frame_logger_hooks_f: {msg}')
            else:
                stack = inspect.stack()
                frame, _, _, _, _, _ = stack[1]
                args, _, _, values = inspect.getargvalues(frame)
                method_name = inspect.getframeinfo(frame)[2]
                argstrs = []
                for arg in args[1:]:
                    argstrs.append("%s=%s" % (arg, self._format_value(values[arg])))
                print(f'>>> frame_logger_hooks_t.{method_name}: {", ".join(args)}')
        return 0

    def frame_udm_created(self, func_ea, udm):
        return self._log()
    
    def frame_udm_deleted(self, func_ea, udm_tid, udm):
        return self._log()
    
    def frame_udm_renamed(self, func_ea, udm, oldname):
        return self._log()
    
    def frame_udm_changed(self, func_ea, udm_tid, udmold, udmnew):
        return self._log()
    


# Remove an existing hook on second run
try:
    frame_idp_hook_stat = "un"
    print("Frame IDP hook: checking for hook...")
    framehook
    print("Frame IDP hook: unhooking....")
    frame_idp_hook_stat2 = ""
    framehook.unhook()
    del framehook
except:
    print("Frame IDP hook: not installed, installing now....")
    frame_idp_hook_stat = ""
    frame_idp_hook_stat2 = "un"
    framehook = frame_logger_hooks_t()
    framehook.hook()

print(f'Frame IDB hook {frame_idp_hook_stat}installed. Run the script again to {frame_idp_hook_stat2}install')