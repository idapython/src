"""
summary: log various local type events.

description:
  hooks to be notified about local type IDP events,
  and dump their information to the "Output" window
"""
import inspect
import ida_idp
import ida_ua

class lt_logger_hooks_t(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        self.inhibit_log = 0
    
    def _format_value(self, v):
        return str(v)
    
    def _log(self, msg=None):
        if self.inhibit_log <= 0:
            if msg:
                print(f'>>> lt_logger_hooks_f: {msg}')
            else:
                stack = inspect.stack()
                frame, _, _, _, _, _ = stack[1]
                args, _, _, values = inspect.getargvalues(frame)
                method_name = inspect.getframeinfo(frame)[2]
                argstrs = []
                for arg in args[1:]:
                    argstrs.append("%s=%s" % (arg, self._format_value(values[arg])))
                print(f'>>> lt_logger_hooks_t.{method_name}: {", ".join(args)}')
        return 0

    def lt_udm_created(self, udtname, udm):
        msg = f'UDM {udm.name} has been created in UDT {udtname}'
        return self._log(msg)
    
    def lt_udm_deleted(self, udtname, udm_tid):
        msg = f'UDM tid {udm_tid:x} has been deleted from {udtname}'
        return self._log(msg)
    
    def lt_udm_renamed(self, udtname, udm, oldname):
        msg = f'UDM {oldname} from UDT {udtname} has been renamed to {udm.name}'
        return self._log(msg)
    
    def lt_udm_changed(self, udtname, udm_tid, udmold, udmnew):
        return self._log()
    


# Remove an existing hook on second run
try:
    idp_hook_stat = "un"
    print("Local type IDB hook: checking for hook...")
    lthook
    print("Local type IDB hook: unhooking....")
    idp_hook_stat2 = ""
    lthook.unhook()
    del lthook
except:
    print("local type IDB hook: not installed, installing now....")
    idp_hook_stat = ""
    idp_hook_stat2 = "un"
    lthook = lt_logger_hooks_t()
    lthook.hook()

print(f'Local type IDB hook {idp_hook_stat}installed. Run the script again to {idp_hook_stat2}install')