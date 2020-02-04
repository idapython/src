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
  if ( dbg != NULL )
    dbg->suspended(true);

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

  static ssize_t store_int(int rc, const debug_event_t *, int *warn)
  {
    *warn = rc;
    return 0;
  }

  static ssize_t store_int(int rc, thid_t, ea_t, int *warn)
  {
    *warn = rc;
    return 0;
  }

  // hookgenDBG:methods
virtual void dbg_process_start(pid_t pid, thid_t tid, ea_t ea, const char * modinfo_name, ea_t modinfo_base, asize_t modinfo_size) {qnotused(pid); qnotused(tid); qnotused(ea); qnotused(modinfo_name); qnotused(modinfo_base); qnotused(modinfo_size); }
virtual void dbg_process_exit(pid_t pid, thid_t tid, ea_t ea, int exit_code) {qnotused(pid); qnotused(tid); qnotused(ea); qnotused(exit_code); }
virtual void dbg_process_attach(pid_t pid, thid_t tid, ea_t ea, const char * modinfo_name, ea_t modinfo_base, asize_t modinfo_size) {qnotused(pid); qnotused(tid); qnotused(ea); qnotused(modinfo_name); qnotused(modinfo_base); qnotused(modinfo_size); }
virtual void dbg_process_detach(pid_t pid, thid_t tid, ea_t ea) {qnotused(pid); qnotused(tid); qnotused(ea); }
virtual void dbg_thread_start(pid_t pid, thid_t tid, ea_t ea) {qnotused(pid); qnotused(tid); qnotused(ea); }
virtual void dbg_thread_exit(pid_t pid, thid_t tid, ea_t ea, int exit_code) {qnotused(pid); qnotused(tid); qnotused(ea); qnotused(exit_code); }
virtual void dbg_library_load(pid_t pid, thid_t tid, ea_t ea, const char * modinfo_name, ea_t modinfo_base, asize_t modinfo_size) {qnotused(pid); qnotused(tid); qnotused(ea); qnotused(modinfo_name); qnotused(modinfo_base); qnotused(modinfo_size); }
virtual void dbg_library_unload(pid_t pid, thid_t tid, ea_t ea, const char * info) {qnotused(pid); qnotused(tid); qnotused(ea); qnotused(info); }
virtual void dbg_information(pid_t pid, thid_t tid, ea_t ea, const char * info) {qnotused(pid); qnotused(tid); qnotused(ea); qnotused(info); }
virtual int dbg_exception(pid_t pid, thid_t tid, ea_t ea, int exc_code, bool exc_can_cont, ea_t exc_ea, const char * exc_info) {qnotused(pid); qnotused(tid); qnotused(ea); qnotused(exc_code); qnotused(exc_can_cont); qnotused(exc_ea); qnotused(exc_info); return 0;}
virtual void dbg_suspend_process() {}
virtual int dbg_bpt(thid_t tid, ea_t bptea) {qnotused(tid); qnotused(bptea); return 0;}
virtual int dbg_trace(thid_t tid, ea_t ip) {qnotused(tid); qnotused(ip); return 0;}
virtual void dbg_request_error(int failed_command, int failed_dbg_notification) {qnotused(failed_command); qnotused(failed_dbg_notification); }
virtual void dbg_step_into() {}
virtual void dbg_step_over() {}
virtual void dbg_run_to(pid_t pid, thid_t tid, ea_t ea) {qnotused(pid); qnotused(tid); qnotused(ea); }
virtual void dbg_step_until_ret() {}
virtual void dbg_bpt_changed(int bptev_code, bpt_t * bpt) {qnotused(bptev_code); qnotused(bpt); }
};

ssize_t idaapi DBG_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;

  class DBG_Hooks *proxy = (class DBG_Hooks *)ud;
  debug_event_t *event;
  ssize_t ret = 0;

  try
  {
    switch ( notification_code )
    {
      // hookgenDBG:notifications
case dbg_process_start:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_process_start(event->pid, event->tid, event->ea, event->modinfo().name.c_str(), event->modinfo().base, event->modinfo().size);
}
break;

case dbg_process_exit:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_process_exit(event->pid, event->tid, event->ea, event->exit_code());
}
break;

case dbg_process_attach:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_process_attach(event->pid, event->tid, event->ea, event->modinfo().name.c_str(), event->modinfo().base, event->modinfo().size);
}
break;

case dbg_process_detach:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_process_detach(event->pid, event->tid, event->ea);
}
break;

case dbg_thread_start:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_thread_start(event->pid, event->tid, event->ea);
}
break;

case dbg_thread_exit:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_thread_exit(event->pid, event->tid, event->ea, event->exit_code());
}
break;

case dbg_library_load:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_library_load(event->pid, event->tid, event->ea, event->modinfo().name.c_str(), event->modinfo().base, event->modinfo().size);
}
break;

case dbg_library_unload:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_library_unload(event->pid, event->tid, event->ea, event->info().c_str());
}
break;

case dbg_information:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_information(event->pid, event->tid, event->ea, event->info().c_str());
}
break;

case dbg_exception:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  int * warn = va_arg(va, int *);
  int _tmp = proxy->dbg_exception(event->pid, event->tid, event->ea, event->exc().code, event->exc().can_cont, event->exc().ea, event->exc().info.c_str());
  ret = DBG_Hooks::store_int(_tmp, event, warn);
}
break;

case dbg_suspend_process:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  qnotused(event);
  proxy->dbg_suspend_process();
}
break;

case dbg_bpt:
{
  thid_t tid = va_arg(va, thid_t);
  ea_t bptea = va_arg(va, ea_t);
  int * warn = va_arg(va, int *);
  int _tmp = proxy->dbg_bpt(tid, bptea);
  ret = DBG_Hooks::store_int(_tmp, tid, bptea, warn);
}
break;

case dbg_trace:
{
  thid_t tid = va_arg(va, thid_t);
  ea_t ip = va_arg(va, ea_t);
  ret = proxy->dbg_trace(tid, ip);
}
break;

case dbg_request_error:
{
  ui_notification_t failed_command = ui_notification_t(va_arg(va, int));
  dbg_notification_t failed_dbg_notification = dbg_notification_t(va_arg(va, int));
  proxy->dbg_request_error((int) failed_command, (int) failed_dbg_notification);
}
break;

case dbg_step_into:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  qnotused(event);
  proxy->dbg_step_into();
}
break;

case dbg_step_over:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  qnotused(event);
  proxy->dbg_step_over();
}
break;

case dbg_run_to:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_run_to(event->pid, event->tid, event->ea);
}
break;

case dbg_step_until_ret:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  qnotused(event);
  proxy->dbg_step_until_ret();
}
break;

case dbg_bpt_changed:
{
  int bptev_code = va_arg(va, int);
  bpt_t * bpt = va_arg(va, bpt_t *);
  proxy->dbg_bpt_changed(bptev_code, bpt);
}
break;

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
  return internal_get_sreg_base(&answer, tid, sreg_value) <= DRC_NONE
       ? BADADDR
       : answer;
}

//-------------------------------------------------------------------------
static ssize_t py_write_dbg_memory(ea_t ea, PyObject *py_buf, size_t size=size_t(-1))
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !dbg_can_query() || !IDAPyStr_Check(py_buf) )
    return -1;
  char *buf = NULL;
  Py_ssize_t sz;
  if ( IDAPyBytes_AsMemAndSize(py_buf, &buf, &sz) < 0 )
    return -1;
  if ( size == size_t(-1) )
    size = size_t(sz);
  return write_dbg_memory(ea, buf, size);
}

/*
#<pydoc>
def dbg_can_query():
    """
    This function can be used to check if the debugger can be queried:
      - debugger is loaded
      - process is suspended
      - process is not suspended but can take requests. In this case some requests like
        memory read/write, bpt management succeed and register querying will fail.
        Check if idaapi.get_process_state() < 0 to tell if the process is suspended
    @return: Boolean
    """
    pass
#</pydoc>
*/

//</inline(py_dbg)>
#endif
