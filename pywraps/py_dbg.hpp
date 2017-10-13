#ifndef __PYDBG__
#define __PYDBG__

//<code(py_dbg)>
//</code(py_dbg)>

//<inline(py_dbg)>

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_manual_regions():
    """
    Returns the manual memory regions
    @return: list(start_ea, end_ea, name, sclass, sbase, bitness, perm)
    """
    pass
#</pydoc>
*/
static PyObject *py_get_manual_regions()
{
  meminfo_vec_t ranges;
  get_manual_regions(&ranges);
  return meminfo_vec_t_to_py(ranges);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def dbg_is_loaded():
    """
    Checks if a debugger is loaded
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool dbg_is_loaded()
{
  return dbg != NULL;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def refresh_debugger_memory():
    """
    Refreshes the debugger memory
    @return: Nothing
    """
    pass
#</pydoc>
*/
static PyObject *refresh_debugger_memory()
{
  invalidate_dbgmem_config();
  invalidate_dbgmem_contents(BADADDR, 0);

  // Ask the debugger to populate debug names
  if ( dbg != NULL && dbg->stopped_at_debug_event != NULL )
    dbg->stopped_at_debug_event(true);

  // Invalidate the cache
  is_mapped(0);

  PYW_GIL_CHECK_LOCKED_SCOPE();
  Py_RETURN_NONE;
}

ssize_t idaapi DBG_Callback(void *ud, int notification_code, va_list va);
class DBG_Hooks
{
public:
  virtual ~DBG_Hooks() { unhook(); }

  bool hook() { return idapython_hook_to_notification_point(HT_DBG, DBG_Callback, this); }
  bool unhook() { return idapython_unhook_from_notification_point(HT_DBG, DBG_Callback, this); }

  static int store_int(int rc, const debug_event_t *, int *warn)
  {
    *warn = rc;
    return 0;
  }

  static int store_int(int rc, thid_t, ea_t, int *warn)
  {
    *warn = rc;
    return 0;
  }

  // hookgenDBG:methods
};

ssize_t idaapi DBG_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;

  class DBG_Hooks *proxy = (class DBG_Hooks *)ud;
  debug_event_t *event;
  int ret = 0;

  try
  {
    switch ( notification_code )
    {
      // hookgenDBG:notifications
    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in DBG Hook function: %s\n", e.getMessage());
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return ret;
}

//------------------------------------------------------------------------
/*
#<pydoc>
def py_list_bptgrps():
    """
    Returns list of breakpoint group names
    @return: A list of strings or None on failure
    """
    pass
#</pydoc>
*/
static PyObject *py_list_bptgrps()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstrvec_t args;
  if ( list_bptgrps(&args) == 0 )
    Py_RETURN_NONE;
  return qstrvec2pylist(args);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def move_bpt_to_grp():
    """
    Sets new group for the breakpoint
    """
    pass
#</pydoc>
*/
static void move_bpt_to_grp(bpt_t *bpt, const char *grp_name)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  set_bpt_group(*bpt, grp_name);
}

/*
#<pydoc>
def internal_get_sreg_base():
    """
    Get the sreg base, for the given thread.

    @return: The sreg base, or BADADDR on failure.
    """
    pass
#</pydoc>
*/
static ea_t py_internal_get_sreg_base(thid_t tid, int sreg_value)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ea_t answer;
  return internal_get_sreg_base(&answer, tid, sreg_value) < 1
       ? BADADDR
       : answer;
}

//</inline(py_dbg)>
#endif
