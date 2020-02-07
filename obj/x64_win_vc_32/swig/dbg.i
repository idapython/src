%module(docstring="IDA Plugin SDK API wrapper: dbg",directors="1",threads="1") ida_dbg
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_DBG
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_DBG
  #define HAS_DEP_ON_INTERFACE_DBG
#endif
#ifndef HAS_DEP_ON_INTERFACE_IDD
  #define HAS_DEP_ON_INTERFACE_IDD
#endif
%include "header.i"
%{
#include <dbg.hpp>
#include <loader.hpp>
%}

%import "idd.i"

%ignore dbg;
%ignore register_srcinfo_provider;
%ignore unregister_srcinfo_provider;
%ignore internal_cleanup_appcall;
%ignore change_bptlocs;
%ignore movbpt_info_t;
%ignore lock_dbgmem_config;
%ignore unlock_dbgmem_config;

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
// TODO: This could be fixed (if needed)
%ignore set_dbgmem_source;

// unusable functions because 'dbg' is not available:
%ignore have_set_options;
%ignore set_dbg_options;
%ignore set_int_dbg_options;
%ignore set_dbg_default_options;

/* %ignore invalidate_dbg_state; */
/* %ignore is_request_running; */

%rename (list_bptgrps) py_list_bptgrps;
%apply qstring *result { qstring *grp_name };
%uncomparable_elements_qvector(bpt_t, bpt_vec_t);

%ignore write_dbg_memory;
%rename (write_dbg_memory) py_write_dbg_memory;

%uncomparable_elements_qvector(tev_reg_value_t, tev_reg_values_t);
%uncomparable_elements_qvector(tev_info_reg_t, tevinforeg_vec_t);
%ignore memreg_info_t::bytes;
%rename (bytes) memreg_info_t_py_bytes;
%uncomparable_elements_qvector(memreg_info_t, memreg_infos_t);

%ignore internal_get_sreg_base;
%rename (internal_get_sreg_base) py_internal_get_sreg_base;

// KLUDGE: since dbg.hpp has first declarations, then definitions
// of inline functions, and SWiG only sees the 2nd part, which
// doesn't have the default argument values, we want to provide
// them here. The proper fix is of course to re-hash dbg.hpp
// so that we avoid this decl + def, and only keep the definitions.
bool run_to(ea_t ea, pid_t pid = NO_PROCESS, thid_t tid = NO_THREAD);
bool request_run_to(ea_t ea, pid_t pid = NO_PROCESS, thid_t tid = NO_THREAD);

%ignore get_insn_tev_reg_val(int, const char *, uint64 *);
%ignore get_insn_tev_reg_result(int, const char *, uint64 *);

%thread;

%nonnul_argument_prototype(
        inline void idaapi set_debugger_event_cond(const char *nonnul_cond),
        const char *nonnul_cond);
%nonnul_argument_prototype(
        inline bool idaapi diff_trace_file(const char *nonnul_filename),
        const char *nonnul_filename);

// We want ALL wrappers around what is declared in dbg.hpp
// to release the GIL when calling into the IDA api: those
// might be very long operations, that even require some
// network traffic.
%include "dbg.hpp"
%nothread;
%ignore DBG_Callback;
%ignore DBG_Hooks::store_int;

%{
//<code(py_dbg)>
//</code(py_dbg)>
%}

//-------------------------------------------------------------------------
//                                 bpt_t
//-------------------------------------------------------------------------
%extend bpt_t
{
  PyObject *condition;
  PyObject *elang;
}

%{
PyObject *bpt_t_condition_get(bpt_t *bpt)
{
  return IDAPyStr_FromUTF8(bpt->cndbody.c_str());
}

void bpt_t_condition_set(bpt_t *bpt, PyObject *val)
{
  if ( IDAPyStr_Check(val) )
    bpt->cndbody = IDAPyBytes_AsString(val);
  else
    PyErr_SetString(PyExc_ValueError, "expected a string");
}

PyObject *bpt_t_elang_get(bpt_t *bpt)
{
  return IDAPyStr_FromUTF8(bpt->get_cnd_elang());
}

void bpt_t_elang_set(bpt_t *bpt, PyObject *val)
{
  if ( IDAPyStr_Check(val) )
  {
    char *cval = IDAPyBytes_AsString(val);
    if ( !bpt->set_cnd_elang(cval) )
      PyErr_SetString(PyExc_ValueError, "too many extlangs");
  }
  else
  {
    PyErr_SetString(PyExc_ValueError, "expected a string");
  }
}
%}

//-------------------------------------------------------------------------
//                              memreg_info_t
//-------------------------------------------------------------------------
%extend memreg_info_t
{
  PyObject *get_bytes() const
  {
    return IDAPyStr_FromUTF8AndSize(
        (const char *) $self->bytes.begin(),
        $self->bytes.size());
  }
  %pythoncode %{
    bytes = property(get_bytes)
  %}
}

%inline %{
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
%}

%pythoncode %{
#<pycode(py_dbg)>
import ida_idaapi
import ida_idd
import ida_expr

def get_tev_reg_val(tev, reg):
    rv = ida_idd.regval_t()
    if get_insn_tev_reg_val(tev, reg, rv):
        if rv.rvtype == ida_idd.RVT_INT:
            return rv.ival

def get_tev_reg_mem_qty(tev):
    ti = tev_info_t()
    if get_tev_info(tev, ti):
        mis = memreg_infos_t()
        if get_insn_tev_reg_mem(tev, mis):
            return mis.size()

def get_tev_reg_mem(tev, idx):
    mis = memreg_infos_t()
    if get_insn_tev_reg_mem(tev, mis):
        if idx < mis.size():
            return mis[idx].bytes

def get_tev_reg_mem_ea(tev, idx):
    ti = tev_info_t()
    if get_tev_info(tev, ti):
        mis = memreg_infos_t()
        if get_insn_tev_reg_mem(tev, mis):
            if idx >= 0 and idx < mis.size():
                return mis[idx].ea

def send_dbg_command(command):
    """
    Send a direct command to the debugger backend, and
    retrieve the result as a string.

    Note: any double-quotes in 'command' must be backslash-escaped.
    Note: this only works with some debugger backends: Bochs, WinDbg, GDB.

    Returns: (True, <result string>) on success, or (False, <Error message string>) on failure
    """
    rv = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(rv, ida_idaapi.BADADDR, """send_dbg_command("%s");""" % command)
    if err:
        return False, "eval_idc_expr() failed: %s" % err
    vtype = ord(rv.vtype)
    if vtype == ida_expr.VT_STR:
        s = rv.c_str()
        if "IDC_FAILURE" in s:
            return False, "eval_idc_expr() reported an error: %s" % s
        return True, s
    elif vtype == ida_expr.VT_LONG:
        return True, str(rv.num)
    else:
        return False, "eval_idc_expr(): wrong return type: %d" % vtype

#</pycode(py_dbg)>
%}
%pythoncode %{
if _BC695:
    import ida_idd
    def get_process_info(n, pi):
        pis = ida_idd.procinfo_vec_t()
        cnt = get_processes(pis)
        if n >= cnt:
            return ida_idd.NO_PROCESS
        pi.name = pis[n].name
        pi.pid = pis[n].pid
        return pi.pid
    def get_process_qty():
        pis = ida_idd.procinfo_vec_t()
        return get_processes(pis)

%}