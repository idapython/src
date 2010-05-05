// SWIG chokes on the original declaration so it is replicated here
typedef struct
{
    ulonglong ival;     // 8:  integer value
    ushort    fval[6];  // 12: floating point value in the internal representation (see ieee.h)
} regval_t;

%ignore dbg;
%ignore get_manual_regions;
%rename (get_manual_regions) py_get_manual_regions;
%ignore set_manual_regions;
%include "dbg.hpp"
%ignore DBG_Callback;
%feature("director") DBG_Hooks;

%{
//<code(py_dbg)>
static PyObject *meminfo_vec_t_to_py(meminfo_vec_t &areas);
//</code(py_dbg)>
%}

%inline %{

//<inline(py_dbg)>
//-------------------------------------------------------------------------
static PyObject *py_get_manual_regions()
{
  meminfo_vec_t areas;
  get_manual_regions(&areas);
  return meminfo_vec_t_to_py(areas);
}

//-------------------------------------------------------------------------
static PyObject *refresh_debugger_memory()
{
  invalidate_dbgmem_config();
  invalidate_dbgmem_contents(BADADDR, BADADDR);
  if ( dbg != NULL && dbg->stopped_at_debug_event != NULL )
    dbg->stopped_at_debug_event(true);
  Py_RETURN_NONE;
}
//</inline(py_dbg)>

int idaapi DBG_Callback(void *ud, int notification_code, va_list va);
class DBG_Hooks
{
public:
    virtual ~DBG_Hooks() {};

    bool hook() { return hook_to_notification_point(HT_DBG, DBG_Callback, this); };
    bool unhook() { return unhook_from_notification_point(HT_DBG, DBG_Callback, this); };
    /* Hook functions to be overridden in Python */
    virtual void dbg_process_start(pid_t pid,
                                   thid_t tid,
                                   ea_t ea,
                                   char *name,
                                   ea_t base,
                                   asize_t size) { };
    virtual void dbg_process_exit(pid_t pid,
                                  thid_t tid,
                                  ea_t ea,
                                  int exit_code) { };
    virtual void dbg_process_attach(pid_t pid,
                                    thid_t tid,
                                    ea_t ea,
                                    char *name,
                                    ea_t base,
                                    asize_t size) { };
    virtual void dbg_process_detach(pid_t pid,
                                    thid_t tid,
                                    ea_t ea) { };
    virtual void dbg_thread_start(pid_t pid,
                                  thid_t tid,
                                  ea_t ea) { };
    virtual void dbg_thread_exit(pid_t pid,
                                 thid_t tid,
                                 ea_t ea,
                                 int exit_code) { };
    virtual void dbg_library_load(pid_t pid,
                                  thid_t tid,
                                  ea_t ea,
                                  char *name,
                                  ea_t base,
                                  asize_t size) { };
    virtual void dbg_library_unload(pid_t pid,
                                    thid_t tid,
                                    ea_t ea,
                                    char *libname) { };
    virtual void dbg_information(pid_t pid,
                                 thid_t tid,
                                 ea_t ea,
                                 char *info) { };
    virtual int dbg_exception(pid_t pid,
                              thid_t tid,
                              ea_t ea,
                              int code,
                              bool can_cont,
                              ea_t exc_ea,
                              char *info) { return 0; };
    virtual void dbg_suspend_process(void) { };
    virtual int dbg_bpt(thid_t tid, ea_t breakpoint_ea) { return 0; };
    virtual int dbg_trace(thid_t tid, ea_t ip) { return 0; };
    virtual void dbg_request_error(ui_notification_t failed_command,
                                   dbg_notification_t failed_dbg_notification) { };
    virtual void dbg_step_into(void) { };
    virtual void dbg_step_over(void) { };
    virtual void dbg_run_to(thid_t tid) { };
    virtual void dbg_step_until_ret(void) { };
};

int idaapi DBG_Callback(void *ud, int notification_code, va_list va)
{
  class DBG_Hooks *proxy = (class DBG_Hooks *)ud;

  debug_event_t *event;
  thid_t tid;
  int *warn;
  ea_t ip;
  ui_notification_t failed_command;
  dbg_notification_t failed_dbg_notification;
  ea_t breakpoint_ea;

  try {
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
      return 0;
    case dbg_process_exit:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_process_exit(event->pid,
        event->tid,
        event->ea,
        event->exit_code);
      return 0;

    case dbg_process_attach:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_process_attach(event->pid,
        event->tid,
        event->ea,
        event->modinfo.name,
        event->modinfo.base,
        event->modinfo.size);
      return 0;

    case dbg_process_detach:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_process_detach(event->pid,
        event->tid,
        event->ea);
      return 0;

    case dbg_thread_start:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_thread_start(event->pid,
        event->tid,
        event->ea);
      return 0;

    case dbg_thread_exit:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_thread_exit(event->pid,
        event->tid,
        event->ea,
        event->exit_code);
      return 0;

    case dbg_library_load:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_library_load(event->pid,
        event->tid,
        event->ea,
        event->modinfo.name,
        event->modinfo.base,
        event->modinfo.size);
      return 0;

    case dbg_library_unload:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_library_unload(event->pid,
        event->tid,
        event->ea,
        event->info);
      return 0;

    case dbg_information:
      event = va_arg(va, debug_event_t *);
      proxy->dbg_information(event->pid,
        event->tid,
        event->ea,
        event->info);
      return 0;

    case dbg_exception:
      event = va_arg(va, debug_event_t *);
      warn = va_arg(va, int *);
      *warn = proxy->dbg_exception(event->pid,
        event->tid,
        event->ea,
        event->exc.code,
        event->exc.can_cont,
        event->exc.ea,
        event->exc.info);
      return 0;

    case dbg_suspend_process:
      proxy->dbg_suspend_process();
      return 0;

    case dbg_bpt:
      tid = va_arg(va, thid_t);
      breakpoint_ea = va_arg(va, ea_t);
      warn = va_arg(va, int *);
      *warn = proxy->dbg_bpt(tid, breakpoint_ea);
      return 0;

    case dbg_trace:
      tid = va_arg(va, thid_t);
      ip = va_arg(va, ea_t);
      return proxy->dbg_bpt(tid, ip);

    case dbg_request_error:
      failed_command = (ui_notification_t)va_arg(va, int);
      failed_dbg_notification = (dbg_notification_t)va_arg(va, int);
      proxy->dbg_request_error(failed_command, failed_dbg_notification);
      return 0;

    case dbg_step_into:
      proxy->dbg_step_into();
      return 0;

    case dbg_step_over:
      proxy->dbg_step_over();
      return 0;

    case dbg_run_to:
      tid = va_arg(va, thid_t);
      proxy->dbg_run_to(tid);
      return 0;

    case dbg_step_until_ret:
      proxy->dbg_step_until_ret();
      return 0;
    }
  }
  catch (Swig::DirectorException &)
  {
    msg("Exception in IDP Hook function:\n");
    if (PyErr_Occurred())
    {
      PyErr_Print();
    }
  }
  return 0;
}

%}
