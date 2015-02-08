// SWIG chokes on the original declaration so it is replicated here
typedef struct
{
    ulonglong ival;     // 8:  integer value
    ushort    fval[6];  // 12: floating point value in the internal representation (see ieee.h)
} regval_t;

%ignore dbg;
%ignore register_srcinfo_provider;
%ignore unregister_srcinfo_provider;
%ignore appcall_info_t;
%ignore get_manual_regions;
%ignore internal_appcall;
%ignore internal_cleanup_appcall;

%ignore source_file_t;
%ignore source_item_t;
%ignore srcinfo_provider_t;
%ignore bpt_location_t::print;
%ignore bpt_t::set_cond;
%ignore bpt_t::eval_cond;
%ignore bpt_t::write;
%ignore bpt_t::erase;
%ignore bpt_t::cndbody;
%ignore bpt_t::get_cnd_elang;
%ignore bpt_t::set_cnd_elang;
%rename (get_manual_regions) py_get_manual_regions;
%ignore set_manual_regions;
%ignore inform_idc_about_debthread;
%ignore is_dbgmem_valid;

%rename (list_bptgrps) py_list_bptgrps;
%apply qstring *result { qstring *grp_name };
%ignore qvector<bpt_t>::operator==;
%ignore qvector<bpt_t>::operator!=;
%ignore qvector<bpt_t>::find;
%ignore qvector<bpt_t>::has;
%ignore qvector<bpt_t>::del;
%ignore qvector<bpt_t>::add_unique;
%template(bpt_vec_t) qvector<bpt_t>;

%ignore internal_get_sreg_base;
%rename (internal_get_sreg_base) py_internal_get_sreg_base;

// We want ALL wrappers around what is declared in dbg.hpp
// to release the GIL when calling into the IDA api: those
// might be very long operations, that even require some
// network traffic.
%thread;
%include "dbg.hpp"
%nothread;
%ignore DBG_Callback;
%feature("director") DBG_Hooks;

%{
//<code(py_dbg)>
static PyObject *meminfo_vec_t_to_py(meminfo_vec_t &areas);
//</code(py_dbg)>
%}

%extend bpt_t
{
  PyObject *condition;
  PyObject *elang;
}
%{
PyObject *bpt_t_condition_get(bpt_t *bpt)
{
  return PyString_FromString(bpt->cndbody.c_str());
}

void bpt_t_condition_set(bpt_t *bpt, PyObject *val)
{
  if ( PyString_Check(val) )
    bpt->cndbody = PyString_AsString(val);
  else
    PyErr_SetString(PyExc_ValueError, "expected a string");
}

PyObject *bpt_t_elang_get(bpt_t *bpt)
{
  return PyString_FromString(bpt->get_cnd_elang());
}

void bpt_t_elang_set(bpt_t *bpt, PyObject *val)
{
  if ( PyString_Check(val) )
  {
    char *cval = PyString_AsString(val);
    if ( !bpt->set_cnd_elang(cval) )
      PyErr_SetString(PyExc_ValueError, "too many extlangs");
  }
  else
  {
    PyErr_SetString(PyExc_ValueError, "expected a string");
  }
}
%}
%inline %{

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
  /* Hook functions to be overridden in Python */
  virtual void dbg_process_start(pid_t pid,
    thid_t tid,
    ea_t ea,
    char *name,
    ea_t base,
    asize_t size) {}
  virtual void dbg_process_exit(pid_t pid,
    thid_t tid,
    ea_t ea,
    int exit_code) {}
  virtual void dbg_process_attach(pid_t pid,
    thid_t tid,
    ea_t ea,
    char *name,
    ea_t base,
    asize_t size) {}
  virtual void dbg_process_detach(pid_t pid,
    thid_t tid,
    ea_t ea) {}
  virtual void dbg_thread_start(pid_t pid,
    thid_t tid,
    ea_t ea) {}
  virtual void dbg_thread_exit(pid_t pid,
    thid_t tid,
    ea_t ea,
    int exit_code) {}
  virtual void dbg_library_load(pid_t pid,
    thid_t tid,
    ea_t ea,
    char *name,
    ea_t base,
    asize_t size) {}
  virtual void dbg_library_unload(pid_t pid,
    thid_t tid,
    ea_t ea,
    char *libname) {}
  virtual void dbg_information(pid_t pid,
    thid_t tid,
    ea_t ea,
    char *info) {}
  virtual int dbg_exception(pid_t pid,
    thid_t tid,
    ea_t ea,
    int code,
    bool can_cont,
    ea_t exc_ea,
    char *info) { return 0; }
  virtual void dbg_suspend_process(void) {}
  virtual int dbg_bpt(thid_t tid, ea_t breakpoint_ea) { return 0; }
  virtual int dbg_trace(thid_t tid, ea_t ip) { return 0; }
  virtual void dbg_request_error(int failed_command,
    int failed_dbg_notification) {}
  virtual void dbg_step_into(void) {}
  virtual void dbg_step_over(void) {}
  virtual void dbg_run_to(pid_t pid, thid_t tid, ea_t ea) {}
  virtual void dbg_step_until_ret(void) {}
};

int idaapi DBG_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;

  class DBG_Hooks *proxy = (class DBG_Hooks *)ud;
  debug_event_t *event;
  int code = 0;

  try
  {
    switch (notification_code)
    {
    case dbg_process_start:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_process_start(event->pid,
        event->tid,
        event->ea,
        event->modinfo.name,
        event->modinfo.base,
        event->modinfo.size);
      break;

    case dbg_process_exit:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_process_exit(
        event->pid,
        event->tid,
        event->ea,
        event->exit_code);
      break;

    case dbg_process_attach:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_process_attach(
        event->pid,
        event->tid,
        event->ea,
        event->modinfo.name,
        event->modinfo.base,
        event->modinfo.size);
      break;

    case dbg_process_detach:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_process_detach(
        event->pid,
        event->tid,
        event->ea);
      break;

    case dbg_thread_start:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_thread_start(
        event->pid,
        event->tid,
        event->ea);
      break;

    case dbg_thread_exit:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_thread_exit(
        event->pid,
        event->tid,
        event->ea,
        event->exit_code);
      break;

    case dbg_library_load:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_library_load(
        event->pid,
        event->tid,
        event->ea,
        event->modinfo.name,
        event->modinfo.base,
        event->modinfo.size);
      break;

    case dbg_library_unload:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_library_unload(
        event->pid,
        event->tid,
        event->ea,
        event->info);
      break;

    case dbg_information:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_information(
        event->pid,
        event->tid,
        event->ea,
        event->info);
      break;

    case dbg_exception:
    {
      event = va_arg(va, debug_event_t *);
      int *warn = va_arg(va, int *);
      *warn = proxy->dbg_exception(
        event->pid,
        event->tid,
        event->ea,
        event->exc.code,
        event->exc.can_cont,
        event->exc.ea,
        event->exc.info);
      break;
    }

    case dbg_suspend_process:
      proxy->dbg_suspend_process();
      break;

    case dbg_bpt:
    {
      thid_t tid = va_arg(va, thid_t);
      ea_t breakpoint_ea = va_arg(va, ea_t);
      int *warn = va_arg(va, int *);
      *warn = proxy->dbg_bpt(tid, breakpoint_ea);
      break;
    }

    case dbg_trace:
    {
      thid_t tid = va_arg(va, thid_t);
      ea_t ip = va_arg(va, ea_t);
      code = proxy->dbg_trace(tid, ip);
      break;
    }

    case dbg_request_error:
    {
      int failed_command = (int)va_argi(va, ui_notification_t);
      int failed_dbg_notification = (int)va_argi(va, dbg_notification_t);
      proxy->dbg_request_error(failed_command, failed_dbg_notification);
      break;
    }

    case dbg_step_into:
      proxy->dbg_step_into();
      break;

    case dbg_step_over:
      proxy->dbg_step_over();
      break;

    case dbg_run_to:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_run_to(
        event->pid,
        event->tid,
        event->ea);
      break;

    case dbg_step_until_ret:
      proxy->dbg_step_until_ret();
      break;
    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in DBG Hook function: %s\n", e.getMessage());
    if (PyErr_Occurred())
      PyErr_Print();
  }
  return code;
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

//</inline(py_dbg)>

%}
