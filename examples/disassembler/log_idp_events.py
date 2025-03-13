"""
summary: react to processor events/notifications

description:
  these hooks will be notified about IDP events, and
  dump their information to the "Output" window

level: intermediate
"""

import inspect

import ida_idp

class idp_logger_hooks_t(ida_idp.IDP_Hooks):

    def __init__(self):
        ida_idp.IDP_Hooks.__init__(self)
        self.inhibit_log = 0;

    def _format_value(self, v):
        return str(v)

    def _log(self, msg=None):
        if self.inhibit_log <= 0:
            if msg:
                print(">>> idp_logger_hooks_t: %s" % msg)
            else:
                stack = inspect.stack()
                frame, _, _, _, _, _ = stack[1]
                args, _, _, values = inspect.getargvalues(frame)
                method_name = inspect.getframeinfo(frame)[2]
                argstrs = []
                for arg in args[1:]:
                    argstrs.append("%s=%s" % (arg, self._format_value(values[arg])))
                print(">>> idp_logger_hooks_t.%s: %s" % (method_name, ", ".join(argstrs)))
        return 0

    def get_abi_info(self, comp):
        self._log()
        return None, None

idp_hooks = idp_logger_hooks_t()
idp_hooks.hook()
