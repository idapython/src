
//<inline(py_kernwin_viewhooks)>

//---------------------------------------------------------------------------
// View hooks
//---------------------------------------------------------------------------
ssize_t idaapi View_Callback(void *ud, int notification_code, va_list va);
class View_Hooks
{
public:
  virtual ~View_Hooks() { unhook(); }

  bool hook()
  {
    return idapython_hook_to_notification_point(HT_VIEW, View_Callback, this);
  }
  bool unhook()
  {
    return idapython_unhook_from_notification_point(HT_VIEW, View_Callback, this);
  }

  // hookgenVIEW:methods
};
//</inline(py_kernwin_viewhooks)>


//<code(py_kernwin_viewhooks)>
//---------------------------------------------------------------------------
ssize_t idaapi View_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  class View_Hooks *proxy = (class View_Hooks *)ud;
  ssize_t ret = 0;
  try
  {
    switch ( notification_code )
    {
      // hookgenVIEW:notifications
    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in View Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return 0;
}
//</code(py_kernwin_viewhooks)>
