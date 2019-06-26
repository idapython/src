#<pycode(py_idp_notify_when)>
import weakref
class _notify_when_dispatcher_t:

    class _callback_t:
        def __init__(self, fun):
            self.fun = fun
            self.slots = 0

    class _IDP_Hooks(IDP_Hooks):
        def __init__(self, dispatcher):
            IDP_Hooks.__init__(self)
            self.dispatcher = weakref.ref(dispatcher)

        def ev_newfile(self, name):
            return self.dispatcher().dispatch(ida_idaapi.NW_OPENIDB, 0)

        def ev_oldfile(self, name):
            return self.dispatcher().dispatch(ida_idaapi.NW_OPENIDB, 1)

    class _IDB_Hooks(IDB_Hooks):
        def __init__(self, dispatcher):
            IDB_Hooks.__init__(self)
            self.dispatcher = weakref.ref(dispatcher)

        def closebase(self):
            return self.dispatcher().dispatch(ida_idaapi.NW_CLOSEIDB)


    def __init__(self):
        self.idp_hooks = self._IDP_Hooks(self)
        self.idp_hooks.hook()
        self.idb_hooks = self._IDB_Hooks(self)
        self.idb_hooks.hook()
        self.callbacks = []

    def _find(self, fun):
        for idx, cb in enumerate(self.callbacks):
            if cb.fun == fun:
                return idx, cb
        return None, None

    def dispatch(self, slot, *args):
        for cb in self.callbacks[:]: # make a copy, since dispatch() could cause some callbacks to disappear
            if (cb.slots & slot) != 0:
                cb.fun(slot, *args)
        return 0

    def notify_when(self, when, fun):
        _, cb = self._find(fun)
        if cb is None:
            cb = self._callback_t(fun)
            self.callbacks.append(cb)
        if (when & ida_idaapi.NW_REMOVE) != 0:
            cb.slots &= ~(when & ~ida_idaapi.NW_REMOVE)
        else:
            cb.slots |= when
        if cb.slots == 0:
            idx, cb = self._find(cb.fun)
            del self.callbacks[idx]
        return True

#</pycode(py_idp_notify_when)>
