#ifndef __PYDBG__
#define __PYDBG__

//<code(py_dbg)>
static PyObject *meminfo_vec_t_to_py(meminfo_vec_t &areas);
//</code(py_dbg)>

//<inline(py_dbg)>

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_manual_regions():
    """
    Returns the manual memory regions
    @return: list(startEA, endEA, name, sclass, sbase, bitness, perm)
    """
    pass
#</pydoc>
*/
static PyObject *py_get_manual_regions()
{
  meminfo_vec_t areas;
  get_manual_regions(&areas);
  return meminfo_vec_t_to_py(areas);
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
  isEnabled(0);

  PYW_GIL_CHECK_LOCKED_SCOPE();
  Py_RETURN_NONE;
}

int idaapi DBG_Callback(void *ud, int notification_code, va_list va);
class DBG_Hooks
{
public:
  virtual ~DBG_Hooks() { unhook(); }

  bool hook() { return hook_to_notification_point(HT_DBG, DBG_Callback, this); }
  bool unhook() { return unhook_from_notification_point(HT_DBG, DBG_Callback, this); }

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

int idaapi DBG_Callback(void *ud, int notification_code, va_list va)
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
case dbg_process_start:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_process_start(event->pid, event->tid, event->ea, event->modinfo.name, event->modinfo.base, event->modinfo.size);
}
break;

case dbg_process_exit:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_process_exit(event->pid, event->tid, event->ea, event->exit_code);
}
break;

case dbg_process_attach:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_process_attach(event->pid, event->tid, event->ea, event->modinfo.name, event->modinfo.base, event->modinfo.size);
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
  proxy->dbg_thread_exit(event->pid, event->tid, event->ea, event->exit_code);
}
break;

case dbg_library_load:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_library_load(event->pid, event->tid, event->ea, event->modinfo.name, event->modinfo.base, event->modinfo.size);
}
break;

case dbg_library_unload:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_library_unload(event->pid, event->tid, event->ea, event->info);
}
break;

case dbg_information:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  proxy->dbg_information(event->pid, event->tid, event->ea, event->info);
}
break;

case dbg_exception:
{
  const debug_event_t * event = va_arg(va, const debug_event_t *);
  int * warn = va_arg(va, int *);
  int _tmp = proxy->dbg_exception(event->pid, event->tid, event->ea, event->exc.code, event->exc.can_cont, event->exc.ea, event->exc.info);
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
  return internal_get_sreg_base(tid, sreg_value, &answer) < 1
       ? BADADDR
       : answer;
}

//-------------------------------------------------------------------------
static PyObject *py_get_tev_reg_mem(int tev, int reg)
{
  tev_info_t ti;
  memreg_infos_t mis;
  bool ok = get_tev_info(tev, &ti)
         && get_insn_tev_reg_mem(tev, &mis)
         && reg >= 0 && reg < mis.size();
  if ( ok )
  {
    PyObject *py_str = PyString_FromStringAndSize(
            (const char *) mis[reg].bytes.begin(),
            mis[reg].bytes.size());
    return py_str;
  }
  else
  {
    Py_RETURN_NONE;
  }
}

//</inline(py_dbg)>
#endif
