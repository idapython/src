
//<code(py_hexrays_hooks)>
//---------------------------------------------------------------------------
ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t code, va_list va)
{
  // hookgenHEXRAYS:safecall=Hexrays_Hooks
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
Hexrays_Hooks::Hexrays_Hooks(uint32 _flags)
  : hooks_base_t("ida_hexrays.Hexrays_Hooks", NULL, hook_type_t(-1), _flags),
    hooked(false)
{
  hexrays_hooks_instances.push_back(this);
}

//-------------------------------------------------------------------------
Hexrays_Hooks::~Hexrays_Hooks()
{
  hexrays_hooks_instances.del(this);
  unhook();
}

// hookgenHEXRAYS:methodsinfo_def

//</code(py_hexrays_hooks)>

//<inline(py_hexrays_hooks)>
//-------------------------------------------------------------------------
// Hexrays hooks
//---------------------------------------------------------------------------
ssize_t idaapi Hexrays_Callback(void *ud, hexrays_event_t event, va_list va);
class control_graph_t;

// We'll inherit from hooks_base_t to benefit from some of its
// goodies, but the [un]hooking mechanism itself will be different.
struct Hexrays_Hooks : public hooks_base_t
{
  // hookgenHEXRAYS:methodsinfo_decl

  bool hooked;

  Hexrays_Hooks(uint32 _flags=0);
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
#ifdef TESTABLE_BUILD
  qstring dump_state() { return hooks_base_t::dump_state(mappings, mappings_size); }
#endif

  // hookgenHEXRAYS:methods

  ssize_t dispatch(hexrays_event_t code, va_list va)
  {
    ssize_t ret = 0;
    switch ( code )
    {
      // hookgenHEXRAYS:notifications
    }
    return ret;
  }

private:
  static ssize_t handle_create_hint_output(PyObject *o, vdui_t *, qstring *out_hint, int *out_implines)
  {
    ssize_t rc = 0;
    if ( o != NULL && PySequence_Check(o) && PySequence_Size(o) == 3 )
    {
      newref_t py_rc(PySequence_GetItem(o, 0));
      newref_t py_hint(PySequence_GetItem(o, 1));
      newref_t py_implines(PySequence_GetItem(o, 2));
      if ( PyInt_Check(py_rc.o) && PyString_Check(py_hint.o) && PyInt_Check(py_implines.o) )
      {
        char *buf;
        Py_ssize_t bufsize;
        if ( PyString_AsStringAndSize(py_hint.o, &buf, &bufsize) > -1 )
        {
          rc = PyInt_AsLong(py_rc.o);
          qstring tmp(buf, bufsize);
          out_hint->swap(tmp);
          *out_implines = PyInt_AsLong(py_implines.o);
        }
      }
    }
    return rc;
  }
};
//</inline(py_hexrays_hooks)>
