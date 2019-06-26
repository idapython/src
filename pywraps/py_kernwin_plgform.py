from __future__ import print_function
#<pycode(py_kernwin_plgform)>
import sys
class PluginForm(object):
    """
    PluginForm class.

    This form can be used to host additional controls. Please check the PyQt example.
    """

    WOPN_MDI      = 0x01 # no-op
    WOPN_TAB      = 0x02 # no-op
    WOPN_RESTORE  = 0x04
    """
    if the widget is the only widget in a floating area when
    it is closed, remember that area's geometry. The next
    time that widget is created as floating (i.e., WOPN_DP_FLOATING)
    its geometry will be restored (e.g., "Execute script"
    """
    WOPN_ONTOP    = 0x08 # no-op
    WOPN_MENU     = 0x10 # no-op
    WOPN_CENTERED = 0x20 # no-op
    WOPN_PERSIST  = 0x40
    """form will persist until explicitly closed with Close()"""
    WOPN_DP_LEFT    = 0x00010000
    """ Dock widget to the left of dest_ctrl"""
    WOPN_DP_TOP     = 0x00020000
    """ Dock widget above dest_ctrl"""
    WOPN_DP_RIGHT   = 0x00040000
    """ Dock widget to the right of dest_ctrl"""
    WOPN_DP_BOTTOM  = 0x00080000
    """ Dock widget below dest_ctrl"""
    WOPN_DP_INSIDE  = 0x00100000
    """ Create a new tab bar with both widget and dest_ctrl"""
    WOPN_DP_TAB     = 0x00400000
    """
    Place widget into a tab next to dest_ctrl,
    if dest_ctrl is in a tab bar
    (otherwise the same as #WOPN_DP_INSIDE)
    """
    WOPN_DP_BEFORE  = 0x00200000
    """
    place widget before dst_form in the tab bar instead of after
    used with #WOPN_DP_INSIDE and #WOPN_DP_TAB
    """
    WOPN_DP_FLOATING=0x00800000
    """ Make widget floating"""
    WOPN_DP_INSIDE_BEFORE = WOPN_DP_INSIDE | WOPN_DP_BEFORE
    WOPN_DP_TAB_BEFORE = WOPN_DP_TAB | WOPN_DP_BEFORE


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
        for key, modname in [("sip", "sip"), ("QtWidgets", "PyQt5.QtWidgets")]:
            if not hasattr(ctx, key):
                print("Note: importing '%s' module into %s" % (key, ctx))
                import importlib
                setattr(ctx, key, importlib.import_module(modname))


    @staticmethod
    def TWidgetToPyQtWidget(form, ctx = sys.modules['__main__']):
        """
        Convert a TWidget* to a QWidget to be used by PyQt

        @param ctx: Context. Reference to a module that already imported SIP and QtWidgets modules
        """
        if type(form).__name__ == "SwigPyObject":
            ptr_l = long(form)
        else:
            ptr_l = form
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
        as_long = long(ctx.sip.unwrapinstance(w))
        return TWidget__from_ptrval__(as_long)


    @staticmethod
    def TWidgetToPySideWidget(form, ctx = sys.modules['__main__']):
        """
        Use this method to convert a TWidget* to a QWidget to be used by PySide

        @param ctx: Context. Reference to a module that already imported QtWidgets module
        """
        if form is None:
            return None
        if type(form).__name__ == "SwigPyObject":
            # Since 'form' is a SwigPyObject, we first need to convert it to a PyCObject.
            # However, there's no easy way of doing it, so we'll use a rather brutal approach:
            # converting the SwigPyObject to a 'long' (will go through 'SwigPyObject_long',
            # that will return the pointer's value as a long), and then convert that value
            # back to a pointer into a PyCObject.
            ptr_l = long(form)
            from ctypes import pythonapi, c_void_p, py_object
            pythonapi.PyCObject_FromVoidPtr.restype  = py_object
            pythonapi.PyCObject_AsVoidPtr.argtypes = [c_void_p, c_void_p]
            form = pythonapi.PyCObject_FromVoidPtr(ptr_l, 0)
        return ctx.QtGui.QWidget.FromCObject(form)
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


    WCLS_SAVE           = 0x1
    """Save state in desktop config"""

    WCLS_NO_CONTEXT     = 0x2
    """Don't change the current context (useful for toolbars)"""

    WCLS_DONT_SAVE_SIZE = 0x4
    """Don't save size of the window"""

    WCLS_CLOSE_LATER    = 0x8
    """This flag should be used when Close() is called from an event handler"""
#</pycode(py_kernwin_plgform)>

plg = PluginForm()
plg.Show("This is it")

#<pycode_BC695(py_kernwin_plgform)>
PluginForm.FORM_MDI = PluginForm.WOPN_MDI
PluginForm.FORM_TAB = PluginForm.WOPN_TAB
PluginForm.FORM_RESTORE = PluginForm.WOPN_RESTORE
PluginForm.FORM_ONTOP = PluginForm.WOPN_ONTOP
PluginForm.FORM_MENU = PluginForm.WOPN_MENU
PluginForm.FORM_CENTERED = PluginForm.WOPN_CENTERED
PluginForm.FORM_PERSIST = PluginForm.WOPN_PERSIST
PluginForm.FORM_SAVE = PluginForm.WCLS_SAVE
PluginForm.FORM_NO_CONTEXT = PluginForm.WCLS_NO_CONTEXT
PluginForm.FORM_DONT_SAVE_SIZE = PluginForm.WCLS_DONT_SAVE_SIZE
PluginForm.FORM_CLOSE_LATER = PluginForm.WCLS_CLOSE_LATER
#</pycode_BC695(py_kernwin_plgform)>
