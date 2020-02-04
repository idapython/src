
//<code(py_hexrays_hooks)>
//---------------------------------------------------------------------------
ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  class Hexrays_Hooks *proxy = (class Hexrays_Hooks *)ud;
  ssize_t ret = 0;
  try
  {
    switch ( event )
    {
      // hookgenHEXRAYS:notifications
    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in Hexrays Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return ret;
}

//-------------------------------------------------------------------------
static qvector<Hexrays_Hooks*> hexrays_hooks_instances;

//-------------------------------------------------------------------------
static void hexrays_unloading__unhook_hooks(void)
{
  for ( size_t i = 0, n = hexrays_hooks_instances.size(); i < n; ++i )
    hexrays_hooks_instances[i]->unhook();
}

//-------------------------------------------------------------------------
Hexrays_Hooks::Hexrays_Hooks()
  : hooked(false)
{
  hexrays_hooks_instances.push_back(this);
}

//-------------------------------------------------------------------------
Hexrays_Hooks::~Hexrays_Hooks()
{
  hexrays_hooks_instances.del(this);
  unhook();
}
//</code(py_hexrays_hooks)>

//<inline(py_hexrays_hooks)>
//-------------------------------------------------------------------------
// Hexrays hooks
//---------------------------------------------------------------------------
ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va);
class control_graph_t;

class Hexrays_Hooks
{
  friend ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va);
  static ssize_t handle_create_hint_output(PyObject *o, vdui_t *, qstring *out_hint, int *out_implines)
  {
    ssize_t rc = 0;
    if ( o != NULL && PySequence_Check(o) && PySequence_Size(o) == 3 )
    {
      newref_t py_rc(PySequence_GetItem(o, 0));
      newref_t py_hint(PySequence_GetItem(o, 1));
      newref_t py_implines(PySequence_GetItem(o, 2));
      if ( IDAPyInt_Check(py_rc.o) && IDAPyStr_Check(py_hint.o) && IDAPyInt_Check(py_implines.o) )
      {
        char *buf;
        Py_ssize_t bufsize;
        if ( IDAPyBytes_AsMemAndSize(py_hint.o, &buf, &bufsize) > -1 )
        {
          rc = IDAPyInt_AsLong(py_rc.o);
          qstring tmp(buf, bufsize);
          out_hint->swap(tmp);
          *out_implines = IDAPyInt_AsLong(py_implines.o);
        }
      }
    }
    return rc;
  }

  bool hooked;

public:
  Hexrays_Hooks();
  virtual ~Hexrays_Hooks();

  bool hook()
  {
    if ( !hooked )
      hooked = install_hexrays_callback(Hexrays_Callback, this);
    return hooked;
  }
  bool unhook()
  {
    if ( hooked )
      hooked = !remove_hexrays_callback(Hexrays_Callback, this);
    return !hooked;
  }

  // hookgenHEXRAYS:methods
};
//</inline(py_hexrays_hooks)>
