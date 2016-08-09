
#<pycode(py_kernwin_idaview)>
#-------------------------------------------------------------------------
#                             IDAViewWrapper
#-------------------------------------------------------------------------
import ida_idaapi
import _ida_kernwin
class IDAViewWrapper(ida_idaapi.CustomIDAMemo):
    """This class wraps access to native IDA views. See kernwin.hpp file"""
    def __init__(self, title):
        """
        Constructs the IDAViewWrapper object around the view
        whose title is 'title'.

        @param title: The title of the existing IDA view. E.g., 'IDA View-A'
        """
        self._title = title

    def Bind(self):
        return _ida_kernwin.pyidag_bind(self)

    def Unbind(self):
        return _ida_kernwin.pyidag_unbind(self)

#</pycode(py_kernwin_idaview)>
