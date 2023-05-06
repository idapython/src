from __future__ import print_function
#<pycode(py_kernwin_plgform)>
import sys

import ida_idaapi

class PluginForm(object):
    """
    PluginForm class.

    This form can be used to host additional controls. Please check the PyQt example.
    """

    WOPN_MDI      = 0x01 # no-op
    WOPN_TAB      = 0x02 # no-op
    WOPN_RESTORE  = _ida_kernwin.WOPN_RESTORE
    """
    if the widget is the only widget in a floating area when
    it is closed, remember that area's geometry. The next
    time that widget is created as floating (i.e., WOPN_DP_FLOATING)
    its geometry will be restored (e.g., "Execute script"
    """
    WOPN_ONTOP       = 0x08 # no-op
    WOPN_MENU        = 0x10 # no-op
    WOPN_CENTERED    = 0x20 # no-op
    WOPN_PERSIST     = _ida_kernwin.WOPN_PERSIST
    """form will persist until explicitly closed with Close()"""
    WOPN_DP_LEFT     = _ida_kernwin.WOPN_DP_LEFT
    """ Dock widget to the left of dest_ctrl"""
    WOPN_DP_TOP      = _ida_kernwin.WOPN_DP_TOP
    """ Dock widget above dest_ctrl"""
    WOPN_DP_RIGHT    = _ida_kernwin.WOPN_DP_RIGHT
    """ Dock widget to the right of dest_ctrl"""
    WOPN_DP_BOTTOM   = _ida_kernwin.WOPN_DP_BOTTOM
    """ Dock widget below dest_ctrl"""
    WOPN_DP_INSIDE   = _ida_kernwin.WOPN_DP_INSIDE
    """ Create a new tab bar with both widget and dest_ctrl"""
    WOPN_DP_TAB      = _ida_kernwin.WOPN_DP_TAB
    """
    Place widget into a tab next to dest_ctrl,
    if dest_ctrl is in a tab bar
    (otherwise the same as #WOPN_DP_INSIDE)
    """
    WOPN_DP_BEFORE   = _ida_kernwin.WOPN_DP_BEFORE
    """
    place widget before dst_form in the tab bar instead of after
    used with #WOPN_DP_INSIDE and #WOPN_DP_TAB
    """
    WOPN_DP_FLOATING = _ida_kernwin.WOPN_DP_FLOATING
    """
    When floating or in a splitter (i.e., not tabbed),
    use the widget's size hint to determine the best
    geometry (Qt only)
    """
    WOPN_DP_SZHINT   = _ida_kernwin.WOPN_DP_SZHINT
    """ Make widget floating"""
    WOPN_DP_INSIDE_BEFORE = _ida_kernwin.WOPN_DP_INSIDE_BEFORE
    WOPN_DP_TAB_BEFORE = _ida_kernwin.WOPN_DP_TAB_BEFORE

    WOPN_CREATE_ONLY = {}


    def __init__(self):
        """
        """
        self.__clink__ = _ida_kernwin.plgform_new()


    def Show(self, caption, options=0):
        """
        Creates the form if not was not created or brings to front if it was already created

        @param caption: The form caption
        @param options: One of PluginForm.WOPN_ constants
        """
        if options == self.WOPN_CREATE_ONLY:
            options = -1
        else:
            options |= PluginForm.WOPN_DP_TAB|PluginForm.WOPN_RESTORE
        return _ida_kernwin.plgform_show(self.__clink__, self, caption, options)


    @staticmethod
    def _ensure_widget_deps(ctx):
        for modname in ["sip", "QtWidgets"]:
            if not hasattr(ctx, modname):
                import importlib
                setattr(ctx, modname, importlib.import_module("PyQt5." + modname))


    VALID_CAPSULE_NAME = b"$valid$"

    @staticmethod
    def TWidgetToPyQtWidget(tw, ctx = sys.modules['__main__']):
        """
        Convert a TWidget* to a QWidget to be used by PyQt

        @param ctx: Context. Reference to a module that already imported SIP and QtWidgets modules
        """
        if type(tw).__name__ == "SwigPyObject":
            ptr_l = ida_idaapi.long_type(tw)
        else:
            import ctypes
            ctypes.pythonapi.PyCapsule_GetPointer.restype = ctypes.c_void_p
            ctypes.pythonapi.PyCapsule_GetPointer.argtypes = [ctypes.py_object, ctypes.c_char_p]
            ptr_l = ctypes.pythonapi.PyCapsule_GetPointer(tw, PluginForm.VALID_CAPSULE_NAME)
        PluginForm._ensure_widget_deps(ctx)
        vptr = ctx.sip.voidptr(ptr_l)
        return ctx.sip.wrapinstance(vptr.__int__(), ctx.QtWidgets.QWidget)
    FormToPyQtWidget = TWidgetToPyQtWidget


    @staticmethod
    def QtWidgetToTWidget(w, ctx = sys.modules['__main__']):
        """
        Convert a QWidget to a TWidget* to be used by IDA

        @param ctx: Context. Reference to a module that already imported SIP and QtWidgets modules
        """
        PluginForm._ensure_widget_deps(ctx)
        as_long = ida_idaapi.long_type(ctx.sip.unwrapinstance(w))
        return TWidget__from_ptrval__(as_long)


    @staticmethod
    def TWidgetToPySideWidget(tw, ctx = sys.modules['__main__']):
        """
        Use this method to convert a TWidget* to a QWidget to be used by PySide

        @param ctx: Context. Reference to a module that already imported QtWidgets module
        """
        if tw is None:
            return None
        if type(tw).__name__ == "SwigPyObject":
            # Since 'tw' is a SwigPyObject, we first need to convert it to a PyCapsule.
            # However, there's no easy way of doing it, so we'll use a rather brutal approach:
            # converting the SwigPyObject to a 'long' (will go through 'SwigPyObject_long',
            # that will return the pointer's value as a long), and then convert that value
            # back to a pointer into a PyCapsule.
            ptr_l = ida_idaapi.long_type(tw)
            # Warning: this is untested
            import ctypes
            ctypes.pythonapi.PyCapsule_New.restype = ctypes.py_object
            ctypes.pythonapi.PyCapsule_New.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p]
            tw = ctypes.pythonapi.PyCapsule_New(ptr_l, PluginForm.VALID_CAPSULE_NAME, 0)
        return ctx.QtGui.QWidget.FromCapsule(tw)
    FormToPySideWidget = TWidgetToPySideWidget

    def OnCreate(self, form):
        """
        This event is called when the plugin form is created.
        The programmer should populate the form when this event is triggered.

        @return: None
        """
        pass


    def OnClose(self, form):
        """
        Called when the plugin form is closed

        @return: None
        """
        pass


    def Close(self, options):
        """
        Closes the form.

        @param options: Close options (WCLS_SAVE, WCLS_NO_CONTEXT, ...)

        @return: None
        """
        return _ida_kernwin.plgform_close(self.__clink__, options)


    def GetWidget(self):
        """
        Return the TWidget underlying this view.

        @return: The TWidget underlying this view, or None.
        """
        return _ida_kernwin.plgform_get_widget(self.__clink__)


    WCLS_SAVE           = _ida_kernwin.WCLS_SAVE
    """Save state in desktop config"""

    WCLS_NO_CONTEXT     = _ida_kernwin.WCLS_NO_CONTEXT
    """Don't change the current context (useful for toolbars)"""

    WCLS_DONT_SAVE_SIZE = _ida_kernwin.WCLS_DONT_SAVE_SIZE
    """Don't save size of the window"""

    WCLS_DELETE_LATER   = _ida_kernwin.WCLS_DELETE_LATER
    """This flag should be used when Close() is called from an event handler"""

    WCLS_CLOSE_LATER  = WCLS_DELETE_LATER

#</pycode(py_kernwin_plgform)>
