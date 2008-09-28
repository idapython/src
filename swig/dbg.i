// SWIG chokes on the original declaration so it is replicated here
typedef struct
{
    ulonglong ival;     // 8:  integer value
    ushort    fval[6];  // 12: floating point value in the internal representation (see ieee.h)
} regval_t;

%immutable dbg;
%include "dbg.hpp"

%feature("director") DBG_Hooks;

%inline %{

int idaapi DBG_Callback(void *ud, int notification_code, va_list va);
class DBG_Hooks 
{
public:
  virtual ~DBG_Hooks() {};

  bool hook() { return hook_to_notification_point(HT_DBG, DBG_Callback, this); };
  bool unhook() { return unhook_from_notification_point(HT_DBG, DBG_Callback, this); };
  /* Hook functions to be overridden in Python */
  virtual void dbg_process_start(process_id_t pid,
				 thread_id_t tid,
				 ea_t ea,
				 char *name,
				 ea_t base,
				 asize_t size) { };
  virtual void dbg_process_exit(process_id_t pid,
				thread_id_t tid,
				ea_t ea,
				int exit_code) { };
  virtual void dbg_process_attach(process_id_t pid,
				  thread_id_t tid,
				  ea_t ea,
				  char *name,
				  ea_t base,
				  asize_t size) { };
  virtual void dbg_process_detach(process_id_t pid,
				  thread_id_t tid,
				  ea_t ea) { };
  virtual void dbg_thread_start(process_id_t pid,
				thread_id_t tid,
				ea_t ea) { };
  virtual void dbg_thread_exit(process_id_t pid, 
			       thread_id_t tid, 
			       ea_t ea,
			       int exit_code) { };
  virtual void dbg_library_load(process_id_t pid,
				thread_id_t tid,
				ea_t ea,
				char *name,
				ea_t base,
				asize_t size) { };
  virtual void dbg_library_unload(process_id_t pid,
				  thread_id_t tid,
				  ea_t ea,
				  char *libname) { };
  virtual void dbg_information(process_id_t pid,
			       thread_id_t tid,
			       ea_t ea,
			       char *info) { };
  virtual int dbg_exception(process_id_t pid,
			    thread_id_t tid,
			    ea_t ea,
			    int code,
			    bool can_cont,
			    ea_t exc_ea,
			    char *info) { return 0; };
  virtual void dbg_suspend_process(void) { };
  virtual int dbg_bpt(thread_id_t tid, ea_t breakpoint_ea) { return 0; };
  virtual int dbg_trace(thread_id_t tid, ea_t ip) { return 0; };
  virtual void dbg_request_error(ui_notification_t failed_command, 
				 dbg_notification_t failed_dbg_notification) { };
  virtual void dbg_step_into(void) { };
  virtual void dbg_step_over(void) { };
  virtual void dbg_run_to(thread_id_t tid) { };
  virtual void dbg_step_until_ret(void) { };
};

int idaapi DBG_Callback(void *ud, int notification_code, va_list va)
{
  class DBG_Hooks *proxy = (class DBG_Hooks *)ud;

  debug_event_t *event;
  thread_id_t tid;
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
	tid = va_arg(va, thread_id_t);
	breakpoint_ea = va_arg(va, ea_t);
	warn = va_arg(va, int *);
	*warn = proxy->dbg_bpt(tid, breakpoint_ea);
	return 0;

      case dbg_trace:
	tid = va_arg(va, thread_id_t);
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
	tid = va_arg(va, thread_id_t);
	proxy->dbg_run_to(tid);
	return 0;

      case dbg_step_until_ret:
	proxy->dbg_step_until_ret();
	return 0;
      }
  }
  catch (Swig::DirectorException &e) 
    { 
      msg("Exception in IDP Hook function:\n"); 
      if (PyErr_Occurred())
	{
	  PyErr_Print();
	}
    }
}
%}
