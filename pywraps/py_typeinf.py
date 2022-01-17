#<pycode(py_typeinf)>

import ida_idaapi
ida_idaapi._listify_types(
    reginfovec_t)

#
# When turning off BC695, 'idati' would still remain available
#
_real_cvar = cvar
_notify_idati = ida_idaapi._make_one_time_warning_message("idati", "get_idati()")

class _wrap_cvar(object):
    def __getattr__(self, attr):
        if attr == "idati":
            _notify_idati()
            return get_idati()
        return getattr(_real_cvar, attr)

    def __setattr__(self, attr, value):
        if attr != "idati":
            setattr(_real_cvar, attr, value)

cvar = _wrap_cvar()

#</pycode(py_typeinf)>
