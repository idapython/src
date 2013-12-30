import _idaapi

#<pycode(py_plgform)>
class PluginForm(object):
    """
    PluginForm class.

    This form can be used to host additional controls. Please check the PyQt example.
    """

    FORM_MDI      = 0x01
    """start by default as MDI (obsolete)"""
    FORM_TAB      = 0x02
    """attached by default to a tab"""
    FORM_RESTORE  = 0x04
    """restore state from desktop config"""
    FORM_ONTOP    = 0x08
    """form should be "ontop"""
    FORM_MENU     = 0x10
    """form must be listed in the windows menu (automatically set for all plugins)"""
    FORM_CENTERED = 0x20
    """form will be centered on the screen"""
    FORM_PERSIST  = 0x40
    """form will persist until explicitly closed with Close()"""


    def __init__(self):
        """
        """
        self.__clink__ = _idaapi.plgform_new()



    def Show(self, caption, options = 0):
        """
		Creates the form if not was not created or brings to front if it was already created

        @param caption: The form caption
        @param options: One of PluginForm.FORM_ constants
        """
        options |= PluginForm.FORM_TAB|PluginForm.FORM_MENU|PluginForm.FORM_RESTORE
        return _idaapi.plgform_show(self.__clink__, self, caption, options)


    @staticmethod
    def FormToPyQtWidget(form, ctx = sys.modules['__main__']):
        """
        Use this method to convert a TForm* to a QWidget to be used by PyQt

        @param ctx: Context. Reference to a module that already imported SIP and QtGui modules
        """
        return ctx.sip.wrapinstance(ctx.sip.voidptr(form).__int__(), ctx.QtGui.QWidget)


    @staticmethod
    def FormToPySideWidget(form, ctx = sys.modules['__main__']):
        """
        Use this method to convert a TForm* to a QWidget to be used by PySide

        @param ctx: Context. Reference to a module that already imported QtGui module
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

        @param options: Close options (FORM_SAVE, FORM_NO_CONTEXT, ...)

        @return: None
        """
        return _idaapi.plgform_close(self.__clink__, options)

    FORM_SAVE           = 0x1
    """Save state in desktop config"""

    FORM_NO_CONTEXT     = 0x2
    """Don't change the current context (useful for toolbars)"""

    FORM_DONT_SAVE_SIZE = 0x4
    """Don't save size of the window"""

    FORM_CLOSE_LATER    = 0x8
    """This flag should be used when Close() is called from an event handler"""
#</pycode(py_plgform)>

plg = PluginForm()
plg.Show("This is it")
