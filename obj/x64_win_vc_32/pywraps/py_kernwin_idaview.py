
#<pycode(py_kernwin_idaview)>
#-------------------------------------------------------------------------
#                             IDAViewWrapper
#-------------------------------------------------------------------------
import _ida_kernwin
class IDAViewWrapper(CustomIDAMemo):
    """
    Deprecated. Use View_Hooks instead.

    Because the lifecycle of an IDAView is not trivial to track (e.g., a user
    might close, then re-open the same disassembly view), this wrapper doesn't
    bring anything superior to the View_Hooks: quite the contrary, as the
    latter is much more generic (and better maps IDA's internal model.)
    """
    def __init__(self, title):
        CustomIDAMemo.__init__(self)
        self._title = title

    def Bind(self):
        rc = _ida_kernwin.pyidag_bind(self)
        if rc:
            self.hook()
        return rc

    def Unbind(self):
        rc = _ida_kernwin.pyidag_unbind(self)
        if rc:
            self.unhook()
        return rc

#</pycode(py_kernwin_idaview)>
