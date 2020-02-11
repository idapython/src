
//<inline(py_idp_idbhooks)>

//---------------------------------------------------------------------------
// IDB hooks
//---------------------------------------------------------------------------
ssize_t idaapi IDB_Callback(void *ud, int notification_code, va_list va);
class IDB_Hooks
{
public:
  virtual ~IDB_Hooks() { unhook(); }

  bool hook()
  {
    return idapython_hook_to_notification_point(HT_IDB, IDB_Callback, this, false);
  }
  bool unhook()
  {
    return idapython_unhook_from_notification_point(HT_IDB, IDB_Callback, this);
  }

  // hookgenIDB:methods
};
//</inline(py_idp_idbhooks)>


//<code(py_idp_idbhooks)>
//---------------------------------------------------------------------------
ssize_t idaapi IDB_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  class IDB_Hooks *proxy = (class IDB_Hooks *)ud;
  ssize_t ret = 0;
  try
  {
    switch ( notification_code )
    {
      // hookgenIDB:notifications
    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in IDB Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return 0;
}
//</code(py_idp_idbhooks)>
