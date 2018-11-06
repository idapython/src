
import sys

${IMPORTS}

# guerilla-patch a few unfortunate overrides
from ida_funcs import set_func_start
from ida_funcs import set_func_end
from ida_dbg import dbg_can_query

class idaapi_Cvar(object):
    def __init__(self):
        # prevent endless recursion
        object.__setattr__(self, "modules", "${MODULES}".split(","))
        object.__setattr__(self, "cvars_entries", dict())

    def _get_module_cvar(self, modname):
        mod = sys.modules["ida_%s" % modname]
        cv, entries = None, None
        if hasattr(mod, "cvar"):
            cv = getattr(mod, "cvar")
            entries = []
            if cv:
                if modname in self.cvars_entries.keys():
                    entries = self.cvars_entries[modname]
                else:
                    # Parse 'str' version of cvar. Although this is braindeader than
                    # braindead, I'm not sure there's another way to do it.
                    entries_s = str(cv)
                    entries = entries_s[1:len(entries_s)-1].split(", ")
                    self.cvars_entries[modname] = entries
        return cv, entries

    def __getattr__(self, attr):
        for mod in self.modules:
            cv, entries = self._get_module_cvar(mod)
            if cv and attr in entries:
                return getattr(cv, attr)

    def __setattr__(self, attr, value):
        for mod in self.modules:
            cv, entries = self._get_module_cvar(mod)
            if cv and attr in entries:
                setattr(cv, attr, value)


cvar = idaapi_Cvar()
