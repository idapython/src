
//<inline(py_idp_idbhooks)>

//---------------------------------------------------------------------------
// IDB hooks
//---------------------------------------------------------------------------
int idaapi IDB_Callback(void *ud, int notification_code, va_list va);
class IDB_Hooks
{
public:
  virtual ~IDB_Hooks() { unhook(); }

  bool hook()
  {
    return hook_to_notification_point(HT_IDB, IDB_Callback, this);
  }
  bool unhook()
  {
    return unhook_from_notification_point(HT_IDB, IDB_Callback, this);
  }

  // hookgenIDB:methods
};
//</inline(py_idp_idbhooks)>


//<code(py_idp_idbhooks)>
//---------------------------------------------------------------------------
int idaapi IDB_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  class IDB_Hooks *proxy = (class IDB_Hooks *)ud;
  int ret = 0;
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
