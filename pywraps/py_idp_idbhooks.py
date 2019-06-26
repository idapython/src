
#<pycode(py_idp_idbhooks)>

class _processor_t_Trampoline_IDB_Hooks(IDB_Hooks):
    def __init__(self, proc):
        IDB_Hooks.__init__(self, ida_idaapi.HBF_CALL_WITH_NEW_EXEC | ida_idaapi.HBF_VOLATILE_METHOD_SET)
        import weakref
        self.proc = weakref.ref(proc)
        for key in dir(self):
            if not key.startswith("_") and not key in ["proc"]:
                thing = getattr(self, key)
                if hasattr(thing, "__call__"):
                    setattr(self, key, self.__make_parent_caller(key))

    def __dummy(self, *args):
        return 0

    def __make_parent_caller(self, key):
        # we can't get the method at this point, as it'll be bound
        # to the processor_t instance, which means it'll increase
        # the reference counting
        def call_parent(*args):
            return getattr(self.proc(), key, self.__dummy)(*args)
        return call_parent

#</pycode(py_idp_idbhooks)>

