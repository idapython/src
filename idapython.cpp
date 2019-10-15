//---------------------------------------------------------------------
// IDAPython - Python plugin for Interactive Disassembler
//
// Copyright (c) The IDAPython Team <idapython@googlegroups.com>
//
// All rights reserved.
//
// For detailed copyright information see the file COPYING in
// the root of the distribution archive.
//---------------------------------------------------------------------
// python.cpp - Main plugin code
//---------------------------------------------------------------------
#include <Python.h>

//-------------------------------------------------------------------------
// This define fixes the redefinition of ssize_t
#ifdef HAVE_SSIZE_T
#define _SSIZE_T_DEFINED 1
#endif

// Python defines snprintf macro so we need to allow it
#define USE_DANGEROUS_FUNCTIONS
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <ida_highlighter.hpp>

#if defined (PY_MAJOR_VERSION) && (PY_MAJOR_VERSION < 3)
// in Python 2.x many APIs accept char * instead of const char *
GCC_DIAG_OFF(write-strings)
#endif

#ifdef PY3
#  define PYCODE_OBJECT_TO_PYEVAL_ARG(Expr) (Expr)
#else
#  define PYCODE_OBJECT_TO_PYEVAL_ARG(Expr) ((PyCodeObject *) Expr)
#endif

#include "extapi.hpp"
#include "extapi.cpp"

ext_api_t extapi;

#include "pywraps.hpp"
#include "pywraps.cpp"

//-------------------------------------------------------------------------
// Defines and constants

// Python-style version tuple comes from the makefile
// Only the serial and status is set here
#define VER_SERIAL 0
#define VER_STATUS "final"
#define IDAPYTHON_RUNSTATEMENT                   0
#define IDAPYTHON_ENABLE_EXTLANG                 3
#define IDAPYTHON_DISABLE_EXTLANG                4
#define PYTHON_DIR_NAME                          "python"
#define S_IDAPYTHON                              "IDAPython"
#define S_INIT_PY                                "init.py"
static const char S_IDC_ARGS_VARNAME[] =         "ARGV";
static const char S_IDC_EXEC_PYTHON[] =          "exec_python";
static const char S_IDC_EVAL_PYTHON[] =          "eval_python";
static const char S_IDAPYTHON_DATA_NODE[] =      "IDAPython_Data";

//-------------------------------------------------------------------------
// Types

//
enum script_run_when
{
  RUN_ON_DB_OPEN = 0,  // run script after opening database (default)
  RUN_ON_UI_READY = 1, // run script when UI is ready
  RUN_ON_INIT = 2,     // run script immediately on plugin load (shortly after IDA starts)
};

//-------------------------------------------------------------------------
// Global variables
static bool g_instance_initialized = false; // This instance of the plugin is the one
                                            // that initialized the python interpreter.
static int  g_run_when = -1;
static char g_run_script[QMAXPATH];
static char g_idapython_dir[QMAXPATH];
static qstring requested_plugin_path;

//-------------------------------------------------------------------------
// Prototypes and forward declarations

// // Alias to SWIG_Init
// //lint -esym(526,init_idaapi) not defined
// extern "C" void init_idaapi(void);

// Plugin run() callback
bool idaapi run(size_t);
static PyObject *get_module_globals_from_path(const char *path);
static bool idaapi IDAPython_extlang_eval_expr(
        idc_value_t *rv,
        ea_t /*current_ea*/,
        const char *expr,
        qstring *errbuf);

//lint -e818 could be pointer to const

//-------------------------------------------------------------------------
// This is a simple tracing code for debugging purposes.
// It might evolve into a tracing facility for user scripts.

//#define ENABLE_PYTHON_PROFILING
#ifdef ENABLE_PYTHON_PROFILING
#include "compile.h"
static int tracefunc(PyObject *obj, _frame *frame, int what, PyObject *arg)
{
  PyObject *str;

  /* Catch line change events. */
  /* Print the filename and line number */
  if ( what == PyTrace_LINE )
  {
    str = PyObject_Str(frame->f_code->co_filename);
    if ( str != NULL )
    {
      msg("PROFILING: %s:%d\n", IDAPyStr_AsUTF8(str), frame->f_lineno);
      Py_DECREF(str);
    }
  }
  return 0;
}
#endif

//-------------------------------------------------------------------------
// Helper routines to make Python script execution breakable from IDA
static bool g_ui_ready = false;
static bool g_alert_auto_scripts = true;
static bool g_remove_cwd_sys_path = false;
static bool g_autoimport_compat_idaapi = true;
static bool g_autoimport_compat_ida695 = true;
static bool g_namespace_aware = true;
static bool g_repl_use_sys_displayhook = true;

//-------------------------------------------------------------------------
bool ida_export is_api695_compat_enabled()
{
  return g_autoimport_compat_ida695;
}

//-------------------------------------------------------------------------
// Allowing the user to interrupt a script is not entirely trivial.
// Imagine the following script, that is run in an IDB that uses
// an IDAPython processor module (important!) :
// ---
// while True:
//     gen_disasm_text(dtext, ea, ea + 4, False)
// ---
// This script will call the processor module's out/outop functions in
// order to generate the text. If the processor module behaves
// correctly (i.e., doesn't take forever to generate said text), if the
// user presses 'Cancel' once the wait dialog box shows, what we want
// to cancel is _this_ script above: we don't want to interrupt the
// processor module while it's doing its thing!
// In order to do that, we will have to remember the time-of-entry of
// various entry points:
//  - IDAPython_extlang_compile_file
//  - IDAPython_RunStatement
//  - ... and more importantly in this case:
//  - IDAPython_extlang_call_method (called by the IDA kernel to generate text)
//
// Of course, in case the processor module's out/outop misbehaves, we still
// want the ability to cancel that operation. The following code allows for
// that, too.

//-------------------------------------------------------------------------
struct exec_entry_t
{
  time_t etime;
  exec_entry_t() { reset_start_time(); }
  void reset_start_time() { etime = time(NULL); }
};
DECLARE_TYPE_AS_MOVABLE(exec_entry_t);
typedef qvector<exec_entry_t> exec_entries_t;

//-------------------------------------------------------------------------
struct execution_t
{
  exec_entries_t entries;
  int timeout;
  uint32 steps_before_action;
  bool wait_box_shown;
  bool interruptible_state;

  execution_t()
    : timeout(2),
      steps_before_action(0),
      wait_box_shown(false),
      interruptible_state(true)
  {
    reset_steps();
  }
  void reset_steps();
  void push();
  void pop();
  bool can_interrupt_current(time_t now) const;
  void reset_current_start_time();
  void stop_tracking();
  void sync_to_present_time();
  void maybe_hide_wait_box();
  void set_interruptible(bool intr) { interruptible_state = intr; }
  bool is_our_wait_box_in_charge() const;
  static int on_trace(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg);
};
static execution_t execution;

//-------------------------------------------------------------------------
typedef qvector<bool> idapython_wait_box_requests_t;
static idapython_wait_box_requests_t idapython_wait_box_requests;
static inline bool idapython_is_user_waitbox_shown()
{
  return idapython_wait_box_requests.has(false);
}

//-------------------------------------------------------------------------
//lint -esym(683,show_wait_box) function 'show_wait_box' #define'd, semantics may be lost
//lint -esym(750,show_wait_box) local macro '' not referenced
//lint -esym(750,hide_wait_box) local macro '' not referenced
void ida_export idapython_show_wait_box(
        bool internal,
        const char *message)
{
  idapython_wait_box_requests.push_back(internal);
#undef show_wait_box
  show_wait_box("%s", message);
#define show_wait_box USE_IDAPYTHON_SHOW_WAIT_BOX
}

//-------------------------------------------------------------------------
void ida_export idapython_hide_wait_box()
{
  if ( !idapython_wait_box_requests.empty() )
  {
    idapython_wait_box_requests.pop_back();
    execution.reset_current_start_time();
  }
#undef hide_wait_box
  hide_wait_box();
#define hide_wait_box USE_IDAPYTHON_HIDE_WAIT_BOX
}


// #define LOG_EXEC 1
#ifdef LOG_EXEC
#define LEXEC(...) msg("IDAPython exec: " __VA_ARGS__)
#else
#define LEXEC(...)
#endif

//-------------------------------------------------------------------------
void execution_t::reset_steps()
{
  // we want to trace/check the time about every 10 steps. But we don't
  // want it to be exactly 10 steps, or we might never make important
  // checks because the tracing happens always at the wrong point.
  // E.g., imagine the following loop:
  // ---
  // while True:
  //     gen_disasm_text(dtext, ea, ea + 4, False)
  // ---
  // If we never hit the 'trace' callback while in the 'while True' loop
  // but always when performing the call to the processor module's 'out/outop'
  // then the loop will never stop. That was happening on windows (optimized.)
  steps_before_action = 1 + rand() % 20;
}

//-------------------------------------------------------------------------
void execution_t::push()
{
  if ( entries.empty() )
    extapi.PyEval_SetTrace_ptr((Py_tracefunc) execution_t::on_trace, NULL); //lint !e611 cast between pointer to function type '' and pointer to object type 'void *'
  entries.push_back();
  LEXEC("push() (now: %d entries)\n", int(entries.size()));
}

//-------------------------------------------------------------------------
void execution_t::pop()
{
  entries.pop_back();
  if ( entries.empty() )
    stop_tracking();
  LEXEC("pop() (now: %d entries)\n", int(entries.size()));
}

//-------------------------------------------------------------------------
void execution_t::stop_tracking()
{
  extapi.PyEval_SetTrace_ptr(NULL, NULL);
  maybe_hide_wait_box();
}

//-------------------------------------------------------------------------
void execution_t::sync_to_present_time()
{
  time_t now = time(NULL);
  for ( size_t i = 0, n = entries.size(); i < n; ++i )
    entries[i].etime = now;
  maybe_hide_wait_box();
}

//-------------------------------------------------------------------------
void execution_t::maybe_hide_wait_box()
{
  if ( wait_box_shown )
  {
    LEXEC("execution_t (%p)::maybe_hide_wait_box() hiding dialog\n", this);
    idapython_hide_wait_box();
    wait_box_shown = false;
  }
}

//-------------------------------------------------------------------------
bool execution_t::can_interrupt_current(time_t now) const
{
  LEXEC("can_interrupt_current(): nentries: %d\n", int(entries.size()));
  if ( entries.empty() || timeout <= 0 || !interruptible_state )
    return false;
  const exec_entry_t &last = entries.back();
  bool can = (now - last.etime) > timeout;
  LEXEC("can_interrupt_current(): last: %d, now: %d (-> %d)\n",
        int(last.etime), int(now), can);
  return can;
}

//-------------------------------------------------------------------------
void execution_t::reset_current_start_time()
{
  if ( !entries.empty() )
  {
    LEXEC("reset_current_start_time()\n");
    entries.back().reset_start_time();
  }
}

//------------------------------------------------------------------------
int execution_t::on_trace(PyObject *obj, PyFrameObject *frame, int what, PyObject *arg)
{
  LEXEC("on_trace() (steps=%d, nentries=%d)\n",
        int(execution.steps_before_action),
        int(execution.entries.size()));
  // we don't want to query for time at every trace event
  if ( execution.steps_before_action-- > 0 )
    return 0;

  if ( get_active_modal_widget() != NULL )
  {
    LEXEC("on_trace()::a modal widget is active. Not showing our 'interrupt dialog'.\n");
    return 0;
  }

  execution.reset_steps();

  if ( idapython_is_user_waitbox_shown() )
  {
    LEXEC("on_trace()::a user wait dialog is currently shown. Not showing our 'interrupt dialog'.\n");
    return 0;
  }

  time_t now = time(NULL);
  LEXEC("on_trace()::now: %d\n", int(now));
  if ( execution.can_interrupt_current(now) )
  {
    const bool user_clicked_cancel = user_cancelled();
    LEXEC("on_trace()::can_interrupt. 'Interrupt dialog' shown=%d, user cancelled=%d\n",
          int(execution.wait_box_shown),
          int(user_clicked_cancel));
    if ( execution.wait_box_shown )
    {
      if ( user_clicked_cancel )
      {
        if ( PyErr_Occurred() == NULL )
        {
          LEXEC("on_trace()::INTERRUPTING (setting 'User interrupted' exception) at line %d\n",
                PyFrame_GetLineNumber(frame));
          PyErr_SetString(PyExc_KeyboardInterrupt, "User interrupted");
        }
        return -1;
      }
    }
    else
    {
      if ( !user_clicked_cancel )
      {
        LEXEC("on_trace()::showing wait dialog\n");
        idapython_show_wait_box(/*internal=*/ true, "Running Python script");
        execution.wait_box_shown = true;
      }
      else
      {
        LEXEC("on_trace()::not showing wait dialog; user_cancelled()\n");
      }
    }
  }

#ifdef ENABLE_PYTHON_PROFILING
  return tracefunc(obj, frame, what, arg);
#else
  qnotused(obj);
  qnotused(frame);
  qnotused(what);
  qnotused(arg);
  return 0;
#endif
}

//-------------------------------------------------------------------------
void ida_export setup_new_execution(
        new_execution_t *instance,
        bool setup)
{
  if ( setup )
  {
    instance->created = g_ui_ready && execution.timeout > 0;
    if ( instance->created )
    {
      PYW_GIL_CHECK_LOCKED_SCOPE();
      execution.push();
    }
  }
  else
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    execution.pop();
  }
}

//-------------------------------------------------------------------------
void ida_export set_interruptible_state(bool interruptible)
{
  execution.set_interruptible(interruptible);
}

//-------------------------------------------------------------------------
void ida_export prepare_programmatic_plugin_load(const char *path)
{
  requested_plugin_path = path;
}

//-------------------------------------------------------------------------
//lint -esym(714,disable_script_timeout) Symbol not referenced
idaman void ida_export disable_script_timeout()
{
  // Clear timeout
  execution.timeout = 0;

  // Uninstall the trace function and hide the waitbox (if it was shown)
  execution.stop_tracking();
}

//-------------------------------------------------------------------------
//lint -esym(714,set_script_timeout) Symbol not referenced
idaman int ida_export set_script_timeout(int timeout)
{
  // Update the timeout
  qswap(timeout, execution.timeout);

  // Reset the execution time and hide the waitbox (so it is shown again after timeout elapses)
  execution.sync_to_present_time();

  return timeout;
}

//------------------------------------------------------------------------
// Return a formatted error or just print it to the console
static void handle_python_error(
        qstring *errbuf,
        bool clear_error = true)
{
  if ( errbuf != NULL )
    errbuf->clear();

  // No exception?
  if ( !PyErr_Occurred() )
    return;

  PyW_GetError(errbuf, clear_error);
}

//------------------------------------------------------------------------
// Note: The references are borrowed. No need to free them.
static PyObject *get_module_globals(const char *modname=NULL)
{
  if ( modname == NULL || modname[0] == '\0' )
    modname = S_MAIN;
  PyObject *module = PyImport_AddModule(modname);
  return module == NULL ? NULL : PyModule_GetDict(module);
}

//-------------------------------------------------------------------------
static ref_t _get_sys_displayhook()
{
  ref_t h;
  if ( g_repl_use_sys_displayhook )
  {
    ref_t py_sys(PyW_TryImportModule("sys"));
    if ( py_sys != NULL )
      h = PyW_TryGetAttrString(py_sys.o, "displayhook");
  }
  return h;
}

//-------------------------------------------------------------------------
static const char *bomify(qstring *out)
{
  out->insert(0, UTF8_BOM, UTF8_BOM_SZ);
  return out->c_str();
}

//------------------------------------------------------------------------
static void PythonEvalOrExec(
        const char *str,
        const char *filename = "<string>")
{
  // Compile as an expression
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring qstr(str);
  newref_t py_code(Py_CompileString(bomify(&qstr), filename, Py_eval_input));
  if ( py_code == NULL || PyErr_Occurred() )
  {
    // Not an expression?
    PyErr_Clear();

    // Run as a string
    extapi.PyRun_SimpleString_ptr(str);
  }
  else
  {
    PyObject *py_globals = get_module_globals();
    newref_t py_result(
            PyEval_EvalCode(
                    PYCODE_OBJECT_TO_PYEVAL_ARG(py_code.o),
                    py_globals,
                    py_globals));

    if ( py_result == NULL || PyErr_Occurred() )    //-V560 is always false: PyErr_Occurred()
    {
      PyErr_Print();
    }
    else
    {
      ref_t sys_displayhook(_get_sys_displayhook());
      if ( sys_displayhook != NULL )
      {
        //lint -esym(1788, res) is referenced only by its constructor or destructor
        newref_t res(PyObject_CallFunctionObjArgs(sys_displayhook.o, py_result.o, NULL));
      }
      else if ( py_result.o != Py_None )
      {
        bool ok = false;
        if ( PyUnicode_Check(py_result.o) )
        {
          qstring utf8;
#ifdef PY3
          IDAPyStr_AsUTF8(&utf8, py_result.o);
#else
          newref_t py_result_utf8(PyUnicode_AsUTF8String(py_result.o));
          ok = py_result_utf8 != NULL;
          if ( ok )
            IDAPyStr_AsUTF8(&utf8, py_result_utf8.o);
#endif
          msg("%s\n", utf8.c_str());
        }
        else
        {
          qstring result_str;
          ok = PyW_ObjectToString(py_result.o, &result_str);
          if ( ok )
            msg("%s\n", result_str.c_str());
        }

        if ( !ok )
          msg("*** IDAPython: Couldn't convert evaluation result\n");
      }
    }
  }
}

//lint -esym(1788, new_execution_t) is referenced only by its constructor or destructor

//------------------------------------------------------------------------
// Executes a simple string
static bool idaapi IDAPython_extlang_eval_snippet(
        const char *str,
        qstring *errbuf)
{
  PYW_GIL_GET;
  PyObject *globals = get_module_globals();
  bool ok;
  if ( globals == NULL )
  {
    ok = false;
  }
  else
  {
    errbuf->clear();
    PyErr_Clear();
    {
      new_execution_t exec;
      newref_t result(extapi.PyRun_String_ptr(
                              str,
                              Py_file_input,
                              globals,
                              globals));
      ok = result != NULL && !PyErr_Occurred();
      if ( !ok )
        handle_python_error(errbuf);
    }
  }
  if ( !ok && errbuf->empty() )
    *errbuf = "internal error";
  return ok;
}

//------------------------------------------------------------------------
// Simple Python statement runner function for IDC
static error_t idaapi idc_runpythonstatement(
        idc_value_t *argv,
        idc_value_t *res)
{
  qstring errbuf;
  bool ok = IDAPython_extlang_eval_snippet(argv[0].c_str(), &errbuf);

  if ( ok )
    res->set_long(0);
  else
    res->set_string(errbuf);

  return eOk;
}
static const char idc_runpythonstatement_args[] = { VT_STR, 0 };
static const ext_idcfunc_t idc_runpythonstatement_desc =
{
  S_IDC_EXEC_PYTHON,
  idc_runpythonstatement,
  idc_runpythonstatement_args,
  NULL,
  0,
  0
};

//------------------------------------------------------------------------
// Simple Python expression evaluator for IDC
static error_t idaapi idc_eval_python(
        idc_value_t *argv,
        idc_value_t *res)
{
  qstring errbuf;
  const char *snippet = argv[0].c_str();
  bool ok = IDAPython_extlang_eval_expr(res, BADADDR, snippet, &errbuf);
  if ( !ok )
    return throw_idc_exception(res, errbuf.c_str());
  return eOk;
}

static const char idc_eval_python_args[] = { VT_STR, 0 };
static const ext_idcfunc_t idc_eval_python_desc =
{
  S_IDC_EVAL_PYTHON,
  idc_eval_python,
  idc_eval_python_args,
  NULL,
  0,
  0
};

//--------------------------------------------------------------------------
static const cfgopt_t opts[] =
{
  cfgopt_t("SCRIPT_TIMEOUT", &execution.timeout, 0, INT_MAX),
  cfgopt_t("ALERT_AUTO_SCRIPTS", &g_alert_auto_scripts, true),
  cfgopt_t("REMOVE_CWD_SYS_PATH", &g_remove_cwd_sys_path, true),
  cfgopt_t("AUTOIMPORT_COMPAT_IDAAPI", &g_autoimport_compat_idaapi, true),
  cfgopt_t("AUTOIMPORT_COMPAT_IDA695", &g_autoimport_compat_ida695, true),
  cfgopt_t("NAMESPACE_AWARE", &g_namespace_aware, true),
  cfgopt_t("REPL_USE_SYS_DISPLAYHOOK", &g_repl_use_sys_displayhook, true),
};

//-------------------------------------------------------------------------
// Check for the presence of a file in IDADIR/python and complain on error
static bool check_python_dir()
{
  static const char *const script_files[] =
  {
    S_IDC_MODNAME ".py",
    S_INIT_PY,
    "ida_idaapi.py",
    "idautils.py"
  };
  char filepath[QMAXPATH];
  for ( size_t i=0; i < qnumber(script_files); i++ )
  {
    qmakepath(filepath, sizeof(filepath), g_idapython_dir, script_files[i], NULL);
    if ( !qfileexist(filepath) )
    {
      warning("IDAPython: Missing required file: '%s'", script_files[i]);
      return false;
    }
  }

  return true;
}

//-------------------------------------------------------------------------
// This function will execute a script in the main module context
// It does not use 'import', thus the executed script will not yield a new module name
// Caller of this function should call handle_python_error() to clear the exception and print the error
static int PyRunFile(const char *path)
{
#ifdef __NT__
  // if the current disk has no space (sic, the current directory, not the one
  // with the input file), PyRun_File() will die with a cryptic message that
  // C runtime library could not be loaded. So we check the disk space before
  // calling it.
  char curdir[QMAXPATH];
  // check if the current directory is accessible. if not, qgetcwd won't return
  qgetcwd(curdir, sizeof(curdir));
  if ( get_free_disk_space(curdir) == 0 )
  {
    warning("No free disk space on %s, python will not be available", curdir);
    return 0;
  }
#endif

  PYW_GIL_CHECK_LOCKED_SCOPE();

  PyObject *__main__globals = get_module_globals();

  //lint -esym(429, fp) custodial pointer not freed or returned
  FILE *fp = qfopen(path, "rt");
  if ( fp == NULL )
    return 0;
  file_janitor_t fpj(fp);
  qstring contents;
  const uint64 fpsz = qfsize(fp);
  if ( fpsz == 0 )
    return 0;
  contents.resize(fpsz);
  qfread(fp, contents.begin(), fpsz);

  newref_t code(Py_CompileString(contents.c_str(), path, Py_file_input));
  if ( code == NULL )
    return 0;

  newref_t result(PyEval_EvalCode(
                          PYCODE_OBJECT_TO_PYEVAL_ARG(code.o),
                          __main__globals,
                          __main__globals));
  return result != NULL && !PyErr_Occurred();
}

//-------------------------------------------------------------------------
// Execute Python statement(s) from an editor window
void IDAPython_RunStatement(void)
{
  qstring qbuf;
  netnode history;

  // Get the existing or create a new netnode in the database
  history.create(S_IDAPYTHON_DATA_NODE);
  history.getblob(&qbuf, 0, 'A');

  if ( ask_text(&qbuf, 0, qbuf.c_str(), "ACCEPT TABS\nEnter Python expressions") )
  {
    {
      PYW_GIL_GET;
      new_execution_t exec;
      extapi.PyRun_SimpleString_ptr(qbuf.c_str());
    }

    // Store the statement to the database
    history.setblob(qbuf.c_str(), qbuf.size(), 0, 'A');
  }
}

//-------------------------------------------------------------------------
// Convert return value from Python to IDC or report about an error.
// This function also decrements the reference "result" (python variable)
static bool return_python_result(
        idc_value_t *idc_result,
        const ref_t &py_result,
        qstring *errbuf)
{
  if ( errbuf != NULL )
    errbuf->clear();

  if ( py_result == NULL )
  {
    handle_python_error(errbuf);
    return false;
  }

  int cvt = CIP_OK;
  if ( idc_result != NULL )
  {
    idc_result->clear();
    cvt = pyvar_to_idcvar(py_result, idc_result);
    if ( cvt < CIP_OK && errbuf != NULL )
      *errbuf = "ERROR: bad return value";
  }

  return cvt >= CIP_OK;
}

//-------------------------------------------------------------------------
// This function will call the Python function 'idaapi.IDAPython_ExecFile'
// It does not use 'import', thus the executed script will not yield a new module name
// It returns the exception and traceback information.
// We use the Python function to execute the script because it knows how to deal with
// module reloading.
static bool IDAPython_ExecFile(
        const char *FileName,
        PyObject *globals,
        qstring *errbuf,
        const char *idaapi_script = S_IDAAPI_EXECSCRIPT,
        idc_value_t *second_res = NULL,
        bool want_tuple = false)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_execscript(get_idaapi_attr(idaapi_script));
  if ( py_execscript == NULL )
  {
    errbuf->sprnt("Could not find %s.%s ?!", S_IDA_IDAAPI_MODNAME, idaapi_script);
    return false;
  }

  char script[MAXSTR];
  qstrncpy(script, FileName, sizeof(script));
  strrpl(script, '\\', '/');

  if ( globals == NULL )
    globals = get_module_globals();
  newref_t py_script(IDAPyStr_FromUTF8(script));
  borref_t py_false(Py_False);
  newref_t py_ret(PyObject_CallFunctionObjArgs(
                          py_execscript.o,
                          py_script.o,
                          globals,
                          py_false.o,
                          NULL));

  // Failure at this point means the script was interrupted
  bool interrupted = false;
  if ( PyW_GetError(errbuf) || py_ret == NULL )
  {
    PyErr_Clear();
    if ( errbuf->empty() )
      *errbuf = "Script interrupted";
    interrupted = true;
  }

  bool ok = false;
  if ( !interrupted )
  {
    PyObject *ret_o;
    if ( want_tuple )
    {
      if ( second_res != NULL
        && PyTuple_Check(py_ret.o)
        && PyTuple_Size(py_ret.o) == 2 )
      {
        ret_o = PyTuple_GetItem(py_ret.o, 0);   // Borrowed reference
      }
      else
      {
        INTERR(30444);
      }
    }
    else
    {
      ret_o = py_ret.o;
    }

    if ( ret_o == Py_None )   //-V614 uninitialized 'ret_o'
    {
      if ( want_tuple )
      {
        borref_t ret2_o(PyTuple_GetItem(py_ret.o, 1));
        ok = return_python_result(second_res, ret2_o, errbuf);
      }
      else
      {
        ok = true;
      }
    }
    else if ( IDAPyStr_Check(ret_o) )
    {
      IDAPyStr_AsUTF8(errbuf, ret_o);
    }
    else
    {
      INTERR(30154);
    }
  }
  return ok;
}

//-------------------------------------------------------------------------
// Execute the Python script from the plugin
static bool RunScript(const char *script)
{
  qstring errbuf;
  bool ok;
  {
    new_execution_t exec;
    ok = IDAPython_ExecFile(script, /*globals*/ NULL, &errbuf);
  }
  if ( !ok )
    warning("IDAPython: error executing '%s':\n%s", script, errbuf.c_str());

  return ok;
}

//-------------------------------------------------------------------------
// This function parses a name into two different components (if it applies).
// Example:
// parse_py_modname("modname.attrname", mod_buf, attr_buf)
// It splits the full name into two parts.
static bool parse_py_modname(
        const char *full_name,
        char *modname,
        char *attrname,
        size_t sz,
        const char *defmod = S_IDA_IDAAPI_MODNAME)
{
  const char *p = strrchr(full_name, '.');
  if ( p == NULL )
  {
    qstrncpy(modname, defmod, sz);
    qstrncpy(attrname, full_name, sz);
  }
  else
  {
    qstrncpy(modname, full_name, p - full_name + 1);
    qstrncpy(attrname, p + 1, sz);
  }
  return p != NULL;
}

//-------------------------------------------------------------------------
// Run callback for Python external language evaluator
static bool idaapi IDAPython_extlang_call_func(
        idc_value_t *result,
        const char *name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf)
{
  PYW_GIL_GET;
  // Try to extract module name (if any) from the funcname
  char modname[MAXSTR];
  char funcname[MAXSTR];
  bool imported_module = parse_py_modname(name, modname, funcname, MAXSTR);

  bool ok = true;
  PyObject *module = NULL;
  ref_vec_t pargs;
  do
  {
    // Convert arguments to python
    ok = pyw_convert_idc_args(args, nargs, pargs, 0, errbuf);
    if ( !ok )
      break;

    const char *final_modname = imported_module ? modname : S_MAIN;
    module = PyImport_ImportModule(final_modname);
    if ( module == NULL )
    {
      if ( errbuf != NULL )
        errbuf->sprnt("couldn't import module %s", final_modname);
      ok = false;
      break;
    }

    PyObject *globals = PyModule_GetDict(module);
    QASSERT(30157, globals != NULL);

    PyObject *func = PyDict_GetItemString(globals, funcname);
    if ( func == NULL )
    {
      if ( errbuf != NULL )
        errbuf->sprnt("undefined function %s", name);
      ok = false;
      break;
    }

    borref_t code(extapi.PyFunction_GetCode_ptr(func));
    qvector<PyObject*> pargs_ptrs;
    pargs.to_pyobject_pointers(&pargs_ptrs);
#ifdef PY3
    newref_t py_res(PyEval_EvalCodeEx(
                            PYCODE_OBJECT_TO_PYEVAL_ARG(code.o),
                            globals, NULL,
                            pargs_ptrs.begin(),
                            nargs,
                            NULL, 0, NULL, 0, NULL, NULL));
#else
    newref_t py_res(PyEval_EvalCodeEx(
                            PYCODE_OBJECT_TO_PYEVAL_ARG(code.o),
                            globals, NULL,
                            pargs_ptrs.begin(),
                            nargs,
                            NULL, 0, NULL, 0, NULL));
#endif
    ok = return_python_result(result, py_res, errbuf);
  } while ( false );

  if ( imported_module )
    Py_XDECREF(module);
  return ok;
}

//-------------------------------------------------------------------------
static void wrap_in_function(qstring *out, const qstring &body, const char *name)
{
  qstrvec_t lines;
  lines.push_back().sprnt("def %s():\n", name);

  qstring buf(body);
  while ( !buf.empty() && qisspace(buf.last()) ) // dont copy trailing whitespace(s)
    buf.remove_last();

  char *ctx;
  for ( char *p = qstrtok(buf.begin(), "\n", &ctx);
        p != NULL;
        p = qstrtok(NULL, "\n", &ctx) )
  {
    static const char FROM_FUTURE_IMPORT_STMT[] = "from __future__ import";
    if ( strneq(p, FROM_FUTURE_IMPORT_STMT, sizeof(FROM_FUTURE_IMPORT_STMT)-1) )
    {
      lines.insert(lines.begin(), p);
    }
    else
    {
      qstring &s = lines.push_back();
      s.append("    ", 4);
      s.append(p);
    }
  }
  out->qclear();
  for ( size_t i = 0; i < lines.size(); ++i )
  {
    if ( i > 0 )
      out->append('\n');
    out->append(lines[i]);
  }
}

//-------------------------------------------------------------------------
// Compile callback for Python external language evaluator
static bool idaapi IDAPython_extlang_compile_expr(
        const char *name,
        ea_t /*current_ea*/,
        const char *expr,
        qstring *errbuf)
{
  PYW_GIL_GET;
  PyObject *globals = get_module_globals();
  bool isfunc = false;

  qstring qstr(expr);
  PyObject *code = Py_CompileString(bomify(&qstr), "<string>", Py_eval_input);
  if ( code == NULL )
  {
    // try compiling as a list of statements
    // wrap them into a function
    handle_python_error(errbuf);
    qstring func;
    wrap_in_function(&func, expr, name);
    bomify(&func);
    code = Py_CompileString(func.c_str(), "<string>", Py_file_input);
    if ( code == NULL )
    {
      handle_python_error(errbuf);
      return false;
    }
    isfunc = true;
  }

  // Create a function out of code
  PyObject *func = extapi.PyFunction_New_ptr(code, globals);

  if ( func == NULL )
  {
ERR:
    handle_python_error(errbuf);
    Py_XDECREF(code);
    return false;
  }

  int err = PyDict_SetItemString(globals, name, func);
  Py_XDECREF(func);

  if ( err )
    goto ERR;

  if ( isfunc )
  {
    idc_value_t result;
    return IDAPython_extlang_call_func(&result, name, NULL, 0, errbuf);
  }

  return true;
}

//-------------------------------------------------------------------------
// Compile callback for Python external language evaluator
static bool idaapi IDAPython_extlang_compile_file(
        const char *path,
        qstring *errbuf)
{
  PYW_GIL_GET;
  new_execution_t exec;
  PyObject *globals = get_module_globals_from_path(path);
  return IDAPython_ExecFile(path, globals, errbuf);
}

//-------------------------------------------------------------------------
// Load processor module callback for Python external language evaluator
static bool idaapi IDAPython_extlang_load_procmod(
        idc_value_t *procobj,
        // hook_cb_t **idp_notifier,
        // void **idp_notifier_ud,
        // hook_cb_t **idb_notifier,
        // void **idb_notifier_ud,
        const char *path,
        qstring *errbuf)
{
  PYW_GIL_GET;
  bool ok;
  {
    new_execution_t exec;
    PyObject *globals = get_module_globals_from_path(path);
    ok = IDAPython_ExecFile(path, globals, errbuf, S_IDAAPI_LOADPROCMOD, procobj, /*want_tuple=*/ true);
  }
  if ( ok && procobj->is_zero() )
  {
    errbuf->clear();
    ok = false;
  }
  return ok;
}

//-------------------------------------------------------------------------
// Unload processor module callback for Python external language evaluator
static bool idaapi IDAPython_extlang_unload_procmod(
        const char *path,
        qstring *errbuf)
{
  PYW_GIL_GET;
  new_execution_t exec;
  PyObject *globals = get_module_globals_from_path(path);
  return IDAPython_ExecFile(path, globals, errbuf, S_IDAAPI_UNLOADPROCMOD);
}

//-------------------------------------------------------------------------
// Create an object instance
//lint -e605 Increase in pointer capability
static bool idaapi IDAPython_extlang_create_object(
        idc_value_t *result,      // out: created object or exception
        const char *name,         // in: object class name
        const idc_value_t args[], // in: input arguments
        size_t nargs,             // in: number of input arguments
        qstring *errbuf)          // out: error message if evaluation fails
{
  PYW_GIL_GET;
  bool ok = false;
  ref_vec_t pargs;
  do
  {
    // Parse the object name (to get the module and class name)
    char modname[MAXSTR];
    char clsname[MAXSTR];
    parse_py_modname(name, modname, clsname, MAXSTR);

    // Get a reference to the module
    ref_t py_mod(PyW_TryImportModule(modname));
    if ( py_mod == NULL )
    {
      errbuf->sprnt("Could not import module '%s'!", modname);
      break;
    }

    // If the class provides an wraper instantiator, use that
    ref_t py_res;
    if ( nargs == 1 && args[0].vtype == VT_PVOID )
      py_res = try_create_swig_wrapper(py_mod, clsname, args[0].pvoid);
    if ( py_res != NULL )
    {
#ifdef PY3
      PyObject_SetAttrString(py_res.o, S_PY_IDCCVT_ID_ATTR, PyLong_FromLong(PY_ICID_OPAQUE));
#else
      PyObject_SetAttrString(py_res.o, S_PY_IDCCVT_ID_ATTR, PyInt_FromLong(PY_ICID_OPAQUE));
#endif
    }
    else
    {
      // Get the class reference
      ref_t py_cls(PyW_TryGetAttrString(py_mod.o, clsname));
      if ( py_cls == NULL )
      {
        errbuf->sprnt("Could not find class type '%s'!", clsname);
        break;
      }

      // Error during conversion?
      ok = pyw_convert_idc_args(args, nargs, pargs, PYWCVTF_AS_TUPLE, errbuf);
      if ( !ok )
        break;

      // Call the constructor
      py_res = newref_t(PyObject_CallObject(py_cls.o, pargs.empty() ? NULL : pargs[0].o));
    }
    ok = return_python_result(result, py_res, errbuf);
  } while ( false );

  return ok;
}

//-------------------------------------------------------------------------
// Returns the attribute value of a given object from the global scope
static bool idaapi IDAPython_extlang_get_attr(
        idc_value_t *result,    // out: result
        const idc_value_t *obj, // in: object (may be NULL)
        const char *attr)       // in: attribute name
{
  PYW_GIL_GET;
  int cvt = CIP_FAILED;
  do
  {
    // Get a reference to the module
    ref_t py_mod(PyW_TryImportModule(S_MAIN));
    if ( py_mod == NULL )
      break;

    // Object specified:
    // - (1) string contain attribute name in the main module
    // - (2) opaque object (we use it as is)
    ref_t py_obj;
    if ( obj != NULL )
    {
      // (1) Get attribute from main module
      if ( obj->vtype == VT_STR )
      {
        py_obj = PyW_TryGetAttrString(py_mod.o, obj->c_str());
      }
      // (2) see if opaque object
      else
      {
        // Convert object (expecting opaque object)
        cvt = idcvar_to_pyvar(*obj, &py_obj);
        if ( cvt != CIP_OK_OPAQUE ) // Only opaque objects are accepted
        {
          py_obj = ref_t();
          cvt = CIP_FAILED;
          break;
        }
      }
      // Get the attribute reference
      if ( py_obj == NULL )
        break;
    }
    // No object specified:
    else
    {
      // ...then work with main module
      py_obj = py_mod;
    }
    // Special case: if attribute not passed then retrieve the class
    // name associated associated with the passed object
    if ( attr == NULL || attr[0] == '\0' )
    {
      cvt = CIP_FAILED;
      // Get the class
      newref_t cls(PyObject_GetAttrString(py_obj.o, "__class__"));
      if ( cls == NULL )
        break;

      // Get its name
      newref_t name(PyObject_GetAttrString(cls.o, "__name__"));
      if ( name == NULL )
        break;

      // Convert name object to string object
      newref_t string(PyObject_Str(name.o));
      if ( string == NULL )
        break;

      // Convert name python string to a C string
      qstring clsname;
      if ( !IDAPyStr_AsUTF8(&clsname, string.o) )
        break;

      result->set_string(clsname);
      cvt = CIP_OK; //lint !e838
      break;
    }

    ref_t py_attr(PyW_TryGetAttrString(py_obj.o, attr));
    // No attribute?
    if ( py_attr == NULL )
    {
      cvt = CIP_FAILED;
      break;
    }
    // Don't store result
    if ( result == NULL )
    {
      cvt = CIP_OK;
      // Decrement attribute (because of GetAttrString)
    }
    else
    {
      cvt = pyvar_to_idcvar(py_attr, result);
      // // Conversion succeeded and opaque object was passed:
      // // Since the object will be passed to IDC, it is likely that IDC value will be
      // // destroyed and also destroying the opaque object with it. That is an undesired effect.
      // // We increment the reference of the object so that even if the IDC value dies
      // // the opaque object remains. So by not decrement reference after GetAttrString() call
      // // we are indirectly increasing the reference. If it was not opaque then we decrement the reference.
      // if ( cvt >= CIP_OK && cvt != CIP_OK_NODECREF )
      // {
      //   // Decrement the reference (that was incremented by GetAttrString())
      //   py_attr.decref();
      // }
    }
  } while ( false );
  return cvt >= CIP_OK;
}

//-------------------------------------------------------------------------
// Returns the attribute value of a given object from the global scope
//lint -e{818}
static bool idaapi IDAPython_extlang_set_attr(
        idc_value_t *obj,       // in: object name (may be NULL)
        const char *attr,       // in: attribute name
        const idc_value_t &value)
{
  PYW_GIL_GET;
  bool ok = false;
  do
  {
    // Get a reference to the module
    ref_t py_mod(PyW_TryImportModule(S_MAIN));
    if ( py_mod == NULL )
      break;
    ref_t py_obj;
    if ( obj != NULL )
    {
      // Get the attribute reference (from just a name)
      if ( obj->vtype == VT_STR )
      {
        py_obj = PyW_TryGetAttrString(py_mod.o, obj->c_str());
      }
      else
      {
        int cvt = idcvar_to_pyvar(*obj, &py_obj);
        if ( cvt != CIP_OK_OPAQUE )  // Only opaque objects are accepted
          py_obj = ref_t();
      }
      // No object to set_attr on?
      if ( py_obj == NULL )
        break;
    }
    else
    {
      // set_attr on the main module
      py_obj = py_mod;
    }
    // Convert the value
    ref_t py_var;
    int cvt = idcvar_to_pyvar(value, &py_var);
    if ( cvt >= CIP_OK )
    {
      ok = PyObject_SetAttrString(py_obj.o, attr, py_var.o) != -1;
      // if ( cvt != CIP_OK_NODECREF )
      //   Py_XDECREF(py_var);
    }
  } while ( false );
  return ok;
}

//-------------------------------------------------------------------------
// Calculator callback for Python external language evaluator
//lint -e{818}
static bool idaapi IDAPython_extlang_eval_expr(
        idc_value_t *rv,
        ea_t /*current_ea*/,
        const char *expr,
        qstring *errbuf)
{
  PYW_GIL_GET;
  PyObject *globals = get_module_globals();
  bool ok = globals != NULL;
  ref_t result;
  if ( ok )
  {
    {
      new_execution_t exec;
      result = newref_t(extapi.PyRun_String_ptr(expr, Py_eval_input, globals, globals));
    }
    ok = return_python_result(rv, result, errbuf);
  }
  return ok;
}

//-------------------------------------------------------------------------
static bool idaapi IDAPython_extlang_call_method(
        idc_value_t *result,
        const idc_value_t *idc_obj,
        const char *method_name,
        const idc_value_t args[],
        size_t nargs,
        qstring *errbuf)
{
  PYW_GIL_GET;
  // Check for unsupported usage of call_method.
  // Mainly a method call requires an object and a method.
  if ( method_name == NULL )
  {
    *errbuf = "call_method does not support this operation";
    return false;
  }
  // Behave like run()
  else if ( idc_obj == NULL )
  {
    new_execution_t exec;
    return IDAPython_extlang_call_func(result, method_name, args, nargs, errbuf);
  }

  // Holds conversion status of input object
  int obj_cvt;
  bool ok = false;
  ref_vec_t pargs;
  do
  {
    // Convert input object
    ref_t py_obj;
    obj_cvt = idcvar_to_pyvar(*idc_obj, &py_obj);
    if ( obj_cvt < CIP_OK )
    {
      *errbuf = "Failed to convert input object to Python value";
      break;
    }

    ref_t py_method(PyW_TryGetAttrString(py_obj.o, method_name));
    if ( py_method == NULL || !PyCallable_Check(py_method.o) )
    {
      errbuf->sprnt("The input object does not have a callable method called '%s'", method_name);
      break;
    }

    // Convert arguments to python objects
    uint32 flags = PYWCVTF_AS_TUPLE;
    // if we are running a ida_idaapi.plugin_t.run, we want the 'int64'
    // to be converted to an unsigned python long
    if ( streq(method_name, "run") )
    {
      ref_t py_ida_idaapi_mod(PyW_TryImportModule(S_IDA_IDAAPI_MODNAME));
      if ( py_ida_idaapi_mod != NULL )
      {
        ref_t py_plugin_t_cls(PyW_TryGetAttrString(py_ida_idaapi_mod.o, "plugin_t"));
        if ( py_plugin_t_cls != NULL )
        {
          if ( PyObject_IsInstance(py_obj.o, py_plugin_t_cls.o) )
            flags |= PYWCVTF_INT64_AS_UNSIGNED_PYLONG;
        }
      }
    }
    ok = pyw_convert_idc_args(args, nargs, pargs, flags, errbuf);
    if ( !ok )
      break;

    {
      new_execution_t exec;
      newref_t py_res(PyObject_CallObject(py_method.o, pargs.empty() ? NULL : pargs[0].o));
      ok = return_python_result(result, py_res, errbuf);
    }
  } while ( false );

  return ok;
}

//-------------------------------------------------------------------------
struct python_highlighter_t : public ida_syntax_highlighter_t
{
  python_highlighter_t() : ida_syntax_highlighter_t()
  {
    open_strconst = '"';
    close_strconst = '"';
    open_chrconst = '\'';
    close_chrconst = '\'';
    escape_char = '\\';
    preprocessor_char = char(1);
    literal_closer = '\0';
    text_color = HF_DEFAULT;
    comment_color = HF_COMMENT;
    string_color = HF_STRING;
    preprocessor_color = HF_KEYWORD1;
    style = HF_DEFAULT;
    set_open_cmt("#");
    add_multi_line_comment("\"\"\"", "\"\"\"");
    add_multi_line_comment("'''", "'''");
    add_keywords(
      "and|as|assert|break|class|continue|def|"
      "del|elif|else|except|exec|finally|"
      "for|from|global|if|import|in|"
      "is|lambda|not|or|pass|print|"
      "raise|return|try|while|with|yield|"
      "None|True|False",HF_KEYWORD1);
    add_keywords("self", HF_KEYWORD2);
    add_keywords("def", HF_KEYWORD3);
  }
};
static python_highlighter_t python_highlighter;

extlang_t extlang_python =
{
  sizeof(extlang_t),
  0,                  // flags
  0,                  // refcnt
  "Python",           // name
  "py",               // filext
  &python_highlighter,
  IDAPython_extlang_compile_expr,
  IDAPython_extlang_compile_file,
  IDAPython_extlang_call_func,
  IDAPython_extlang_eval_expr,
  IDAPython_extlang_eval_snippet,
  IDAPython_extlang_create_object,
  IDAPython_extlang_get_attr,
  IDAPython_extlang_set_attr,
  IDAPython_extlang_call_method,
  IDAPython_extlang_load_procmod,
  IDAPython_extlang_unload_procmod,
};

//-------------------------------------------------------------------------
idaman void ida_export enable_extlang_python(bool enable)
{
  if ( enable )
    select_extlang(&extlang_python);
  else
    select_extlang(NULL);
}

//-------------------------------------------------------------------------
// Execute a line in the Python CLI
bool idaapi IDAPython_cli_execute_line(const char *line)
{
  PYW_GIL_GET;

  // Do not process empty lines
  if ( line[0] == '\0' )
    return true;

  const char *last_line = strrchr(line, '\n');
  if ( last_line == NULL )
    last_line = line;
  else
    last_line += 1;

  // Skip empty lines
  if ( last_line[0] != '\0' )
  {
    // Line ends with ":" or begins with a space character?
    bool more = last_line[qstrlen(last_line)-1] == ':' || qisspace(last_line[0]);
    if ( more )
      return false;
  }

  //
  // Pseudo commands
  //
  qstring s;
  do
  {
    // Help command?
    if ( line[0] == '?' )
      s.sprnt("help(%s)", line+1);
    // Shell command?
    else if ( line[0] == '!' )
      s.sprnt("idaapi.IDAPython_ExecSystem(r'%s')", line+1);
    else
      break;
    // Patch the command line pointer
    line = s.c_str();
  } while (false);

  {
    new_execution_t exec;
    PythonEvalOrExec(line);
  }

  return true;
}

//-------------------------------------------------------------------------
static bool idaapi IDAPython_cli_find_completions(
        qstrvec_t *out_completions,
        int *out_match_start,
        int *out_match_end,
        const char *line,
        int x)
{
  PYW_GIL_GET;

  ref_t py_fc(get_idaapi_attr(S_IDAAPI_FINDCOMPLETIONS));
  if ( py_fc == NULL )
    return false;

  newref_t py_res(PyObject_CallFunction(py_fc.o, "si", line, x)); //lint !e605 !e1776
  if ( PyErr_Occurred() != NULL )
    return false;
  return idapython_convert_cli_completions(
          out_completions,
          out_match_start,
          out_match_end,
          py_res);
}

//-------------------------------------------------------------------------
static PyObject *get_module_globals_from_path_with_kind(const char *path, const char *kind)
{
  const char *fname = qbasename(path);
  if ( fname != NULL )
  {
    const char *ext = get_file_ext(fname);
    if ( ext == NULL )
      ext = tail(fname);
    else
      --ext;
    if ( ext > fname )
    {
      int len = ext - fname;
      qstring modname;
      modname.sprnt("__%s__%*.*s", kind, len, len, fname);
      return get_module_globals(modname.begin());
    }
  }
  return NULL;
}

//-------------------------------------------------------------------------
static PyObject *get_module_globals_from_path(const char *path)
{
  if ( (extlang_python.flags & EXTLANG_NS_AWARE) != 0 )
  {
    if ( requested_plugin_path == path )
      return get_module_globals_from_path_with_kind(path, PLG_SUBDIR);

    char dirpath[QMAXPATH];
    if ( qdirname(dirpath, sizeof(dirpath), path) )
    {
      const char *dirname = qbasename(dirpath);
      if ( streq(dirname, PLG_SUBDIR)
        || streq(dirname, IDP_SUBDIR)
        || streq(dirname, LDR_SUBDIR) )
      {
        return get_module_globals_from_path_with_kind(path, dirname);
      }
    }
  }
  return NULL;
}

//-------------------------------------------------------------------------
static const cli_t cli_python =
{
  sizeof(cli_t),
  0,
  "Python",
  "Python - IDAPython plugin",
  "Enter any Python expression",
  IDAPython_cli_execute_line,
  NULL,
  NULL,
  IDAPython_cli_find_completions,
};

//-------------------------------------------------------------------------
// Control the Python CLI status
idaman void ida_export enable_python_cli(bool enable)
{
  if ( enable )
    install_command_interpreter(&cli_python);
  else
    remove_command_interpreter(&cli_python);
}

//------------------------------------------------------------------------
// Parse plugin options
void parse_plugin_options()
{
  // Get options from IDA
  const char *options = get_plugin_options(S_IDAPYTHON);
  if ( options == NULL || options[0] == '\0' )
    return;
  qstring obuf(options);
  char *ctx;
  for ( char *p = qstrtok(obuf.begin(), ";", &ctx);
        p != NULL;
        p = qstrtok(NULL, ";", &ctx) )
  {
    qstring opt(p);
    char *sep = qstrchr(opt.begin(), '=');
    bool ok = sep != NULL;
    if ( ok )
    {
      *sep++ = '\0';
      if ( opt == "run_script" )
      {
        qstrncpy(g_run_script, sep, sizeof(g_run_script));
        if ( g_run_when < 0 )
          g_run_when = RUN_ON_DB_OPEN;
      }
      else if ( opt == "run_script_when" )
      {
        qstring when(sep);
        if ( when == "db_open" )
          g_run_when = RUN_ON_DB_OPEN;
        else if ( when == "ui_ready" )
          g_run_when = RUN_ON_UI_READY;
        else if ( when == "init" )
          g_run_when = RUN_ON_INIT;
        else
          warning("Unknown 'run_script_when' directive: '%s'. "
                  "Valid values are: 'db_open', 'ui_ready' and 'init'",
                  when.c_str());
      }
      else if ( opt == "AUTOIMPORT_COMPAT_IDA695" )
      {
        qstring imp(sep);
        if ( imp == "YES" )
          g_autoimport_compat_ida695 = true;
        else if ( imp == "NO" )
          g_autoimport_compat_ida695 = false;
        else
          warning("Unknown 'AUTOIMPORT_COMPAT_IDA695' directive: '%s'. "
                  " Expected 'YES' or 'NO'", imp.c_str());
      }
    }
  }
}

//------------------------------------------------------------------------
// Converts the global IDC variable "ARGV" into a Python variable.
// The arguments will then be accessible via 'idc' module / 'ARGV' variable.
void convert_idc_args()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_args(PyList_New(0));

  idc_value_t *idc_args = find_idc_gvar(S_IDC_ARGS_VARNAME);
  if ( idc_args != NULL )
  {
    idc_value_t attr;
    char attr_name[20] = { "0" };
    for ( int i=1; get_idcv_attr(&attr, idc_args, attr_name) == eOk; i++ )
    {
      PyList_Insert(py_args.o, i, IDAPyStr_FromUTF8(attr.c_str()));
      qsnprintf(attr_name, sizeof(attr_name), "%d", i);
    }
  }

  // Get reference to the IDC module (it is imported by init.py)
  ref_t py_mod(PyW_TryImportModule(S_IDC_MODNAME));
  if ( py_mod != NULL )
    PyObject_SetAttrString(py_mod.o, S_IDC_ARGS_VARNAME, py_args.o);
}

//-------------------------------------------------------------------------
enum module_lifecycle_notification_t
{
  mln_init = 0,
  mln_term,
  mln_closebase
};
static void send_modules_lifecycle_notification(module_lifecycle_notification_t what)
{
  PYW_GIL_GET;
  for ( size_t i = modules_callbacks.size(); i > 0; --i )
  {
    const module_callbacks_t &m = modules_callbacks[i-1];
    switch ( what )
    {
      case mln_init: m.init(); break;
      case mln_term: m.term(); break;
      case mln_closebase: m.closebase(); break;
    }
    if ( PyErr_Occurred() )
    {
      msg("Error during module lifecycle notification:\n");
      PyErr_Print();
    }
  }
}

//------------------------------------------------------------------------
//lint -esym(715,va) Symbol not referenced
static ssize_t idaapi on_ui_notification(void *, int code, va_list)
{
  switch ( code )
  {
    case ui_term:
      {
        PYW_GIL_GET; // This hook gets called from the kernel. Ensure we hold the GIL.
        // Let's make sure there are no non-Free()d forms.
        free_compiled_form_instances();
        // and no live python timers
        // Note: It's ok to put this here, because 'ui_term' is guaranteed
        // to be sent before the PLUGIN_FIX plugins are terminated.
        clear_python_timer_instances();
      }
      break;

    case ui_ready_to_run:
      {
        PYW_GIL_GET; // See above
        g_ui_ready = true;
        extapi.PyRun_SimpleString_ptr("print_banner()");
        if ( g_run_when == RUN_ON_UI_READY )
          RunScript(g_run_script);
      }
      break;

    case ui_database_inited:
      {
        PYW_GIL_GET; // See above
        convert_idc_args();
        if ( g_run_when == RUN_ON_DB_OPEN )
          RunScript(g_run_script);
      }
      break;

    default:
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
//lint -esym(526,til_clear_python_tinfo_t_instances) not defined
static ssize_t idaapi on_idb_notification(void *, int code, va_list)
{
  switch ( code )
  {
    case idb_event::closebase:
      // The til machinery is about to garbage-collect: We must go
      // through all the tinfo_t objects that are embedded in SWIG wrappers,
      // (i.e., that were created from Python) and clear those.
      til_clear_python_tinfo_t_instances();
      send_modules_lifecycle_notification(mln_closebase);
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
#ifdef PY3
static wchar_t *utf8_wchar_t(qvector<wchar_t> *out, const char *in)
{
#ifdef __NT__
  qwstring tmp;
  utf8_utf16(&tmp, in);
  out->qclear();
  out->insert(out->begin(), tmp.begin(), tmp.end());
#else
  const char *p = in;
  while ( *p != '\0' )
  {
    wchar32_t cp = get_utf8_char(&p);
    if ( cp == 0 || cp == BADCP )
      break;
    out->push_back(cp);
  }
  out->push_back(0); // we're not dealing with a qstring; have to do it ourselves
#endif
  return out->begin();
}
#endif // PY3


//-------------------------------------------------------------------------
// - remove current directory (empty entry) from the sys.path
// - add idadir("python")
static void prepare_sys_path()
{
  borref_t path(PySys_GetObject("path"));
  if ( path == nullptr || !PySequence_Check(path.o) )
    return;

  qstring new_path;
  Py_ssize_t path_len = PySequence_Size(path.o);
  if ( path_len > 0 )
  {
    for ( Py_ssize_t i = 0; i < path_len; ++i )
    {
      qstring path_el_utf8;
      newref_t path_el(PySequence_GetItem(path.o, i));
      if ( path_el != nullptr
        && IDAPyStr_Check(path_el.o) > 0
        && IDAPyStr_AsUTF8(&path_el_utf8, path_el.o) )
      {
        if ( path_el_utf8.empty() )
          continue; // skip empty entry
        if ( !new_path.empty() )
          new_path.append(DELIMITER);
        new_path.append(path_el_utf8);
      }
    }
  }
  if ( !new_path.empty() )
    new_path.append(DELIMITER);
  new_path.append(idadir("python"));
#ifdef PY3
  qvector<wchar_t> wpath;
  PySys_SetPath(utf8_wchar_t(&wpath, new_path.c_str()));
#else
  PySys_SetPath(new_path.begin());
#endif
}

//-------------------------------------------------------------------------
// Initialize the Python environment
bool IDAPython_Init(void)
{
  if ( Py_IsInitialized() != 0 )
    return true;

  // Form the absolute path to IDA\python folder
  qmakepath(g_idapython_dir, sizeof(g_idapython_dir),
            idadir(PYTHON_DIR_NAME),
            QSTRINGIZE(PY_MAJOR_VERSION),
            NULL);

  // Check for the presence of essential files
  if ( !check_python_dir() )
    return false;

  char path[QMAXPATH];
  qstring errbuf;
  if ( !extapi.load(&errbuf) )
  {
    warning("Couldn't initialize IDAPython: %s", errbuf.c_str());
    return false;
  }

#ifdef __MAC__
  if ( !extapi.lib_path.empty() )
  {
    // The path will be something like:
    // /System/Library/Frameworks/Python.framework/Versions/2.5/Python
    // We need to strip the last part
    // use static buffer because Py_SetPythonHome() just stores a pointer
    static char pyhomepath[MAXSTR];
    qstrncpy(pyhomepath, extapi.lib_path.c_str(), sizeof(pyhomepath));
    char *lastslash = strrchr(pyhomepath, '/');
    if ( lastslash != NULL )
    {
      *lastslash = 0;
#ifdef PY3
      qvector<wchar_t> buf;
      Py_SetPythonHome(utf8_wchar_t(&buf, pyhomepath));
#else
      Py_SetPythonHome(pyhomepath);
#endif
    }
  }
#endif

  // Read configuration value
  read_config_file("idapython.cfg", opts, qnumber(opts));
  if ( g_alert_auto_scripts )
  {
    if ( pywraps_check_autoscripts(path, sizeof(path))
      && ask_yn(ASKBTN_NO,
                "HIDECANCEL\n"
                "TITLE IDAPython\n"
                "The script '%s' was found in the current directory\n"
                "and will be automatically executed by Python.\n"
                "\n"
                "Do you want to continue loading IDAPython?", path) <= 0 )
    {
      return false;
    }
  }
  parse_plugin_options();

  // Start the interpreter
  Py_InitializeEx(0 /* Don't catch SIGPIPE, SIGXFZ, SIGXFSZ & SIGINT signals */);

  if ( !Py_IsInitialized() )
  {
    warning("IDAPython: Py_InitializeEx() failed");
    return false;
  }

  // remove current directory
  prepare_sys_path();

  // Enable multi-threading support
  if ( !PyEval_ThreadsInitialized() )
    PyEval_InitThreads();

#ifdef Py_DEBUG
  msg("HexraysPython: Python compiled with DEBUG enabled.\n");
#endif

  // Set IDAPYTHON_VERSION in Python
  qstring init_code;
  init_code.sprnt(
          "IDAPYTHON_VERSION=(%d, %d, %d, '%s', %d)\n"
          "IDAPYTHON_REMOVE_CWD_SYS_PATH = %s\n"
          "IDAPYTHON_DYNLOAD_BASE = r\"%s\"\n"
          "IDAPYTHON_DYNLOAD_RELPATH = \"ida_%" FMT_Z "\"\n"
          "IDAPYTHON_COMPAT_AUTOIMPORT_MODULES = %s\n"
          "IDAPYTHON_COMPAT_695_API = %s\n",
          VER_MAJOR, VER_MINOR, VER_PATCH, VER_STATUS, VER_SERIAL,
          g_remove_cwd_sys_path ? "True" : "False",
          idadir(NULL),
          sizeof(ea_t)*8,
          g_autoimport_compat_idaapi ? "True" : "False",
#ifdef BC695
          g_autoimport_compat_ida695 ? "True" : "False"
#else
          "False"
#endif
                  );

  if ( extapi.PyRun_SimpleString_ptr(init_code.c_str()) != 0 )
  {
    warning("IDAPython: error executing bootstrap code");
    return false;
  }

  // Install extlang. Needs to be done before running init.py
  // in case it's calling idaapi.enable_extlang_python(1)
  if ( g_namespace_aware )
    extlang_python.flags |= EXTLANG_NS_AWARE;
  install_extlang(&extlang_python);

  // Execute init.py (for Python side initialization)
  qmakepath(path, MAXSTR, g_idapython_dir, S_INIT_PY, NULL);
  if ( !PyRunFile(path) )
  {
    // Try to fetch a one line error string. We must do it before printing
    // the traceback information. Make sure that the exception is not cleared
    handle_python_error(&errbuf, false);

    // Print the exception traceback
    extapi.PyRun_SimpleString_ptr("import traceback;traceback.print_exc();");

    warning("IDAPython: error executing " S_INIT_PY ":\n"
            "%s\n"
            "\n"
            "Refer to the message window to see the full error log.", errbuf.c_str());
    remove_extlang(&extlang_python);
    return false;
  }

  // Init pywraps and notify_when
  if ( !init_pywraps() )
  {
    warning("IDAPython: init_pywraps() failed!");
    remove_extlang(&extlang_python);
    return false;
  }

#ifdef ENABLE_PYTHON_PROFILING
  extapi.PyEval_SetTrace_ptr(tracefunc, NULL);
#endif

  // Register a exec_python() function for IDC
  add_idc_func(idc_runpythonstatement_desc);
  add_idc_func(idc_eval_python_desc);

  // A script specified on the command line is run
  if ( g_run_when == RUN_ON_INIT )
    RunScript(g_run_script);

  hook_to_notification_point(HT_UI, on_ui_notification);
  hook_to_notification_point(HT_IDB, on_idb_notification);

  // Enable the CLI by default
  enable_python_cli(true);

  // Let all modules perform possible initialization
  send_modules_lifecycle_notification(mln_init);

  PyEval_ReleaseThread(PyThreadState_Get());

  g_instance_initialized = true;
  return true;
}

//-------------------------------------------------------------------------
#ifdef TESTABLE_BUILD
// "user-code-leniency" means that, even in TESTABLE_BUILD builds,
// IDAPython will accept that some things are left in an undesirable,
// but recuperable state (e.g., remaining hooks.)
// This should *ONLY* be used for tests that rely on user code that
// is in such a shape that it would require significant changes to
// have it perform proper cleanup, which means that it would have to
// diverge from the original user's code, which means that we
// would have to maintain our own branch of it, which is not
// the best idea of the world, overhead-wise.
static int _is_user_code_lenient = -1;
static bool is_user_code_lenient()
{
  if ( _is_user_code_lenient < 0 )
    _is_user_code_lenient = qgetenv("IDAPYTHON_USER_CODE_LENIENT");
  return _is_user_code_lenient > 0;
}

#endif

//-------------------------------------------------------------------------
// Cleaning up Python
void IDAPython_Term(void)
{
  if ( !g_instance_initialized || Py_IsInitialized() == 0 )
    return;

  if ( PyGILState_GetThisThreadState() )
  {
    // Note: No 'PYW_GIL_GET' here, as it would try to release
    // the state after 'Py_Finalize()' has been called.
    // ...nor is it a good idea to try to put it in its own scope,
    // as it will PyGILState_Release() the current thread & GIL, and
    // Py_Finalize() itself wouldn't be happy then.
    PyGILState_Ensure();
  }

  // Let all modules perform possible de-initialization
  send_modules_lifecycle_notification(mln_term);

  unhook_from_notification_point(HT_IDB, on_idb_notification);
  unhook_from_notification_point(HT_UI, on_ui_notification);

  // Remove the CLI
  enable_python_cli(false);

  // Remove the extlang
  remove_extlang(&extlang_python);

  // De-init pywraps
  deinit_pywraps();

  // Uninstall IDC function
  del_idc_func(idc_eval_python_desc.name);
  del_idc_func(idc_runpythonstatement_desc.name);

  // Shut the interpreter down
  Py_Finalize();
  g_instance_initialized = false;

#ifdef TESTABLE_BUILD
  if ( !is_user_code_lenient() ) // Check that all hooks were unhooked
    QASSERT(30509, hook_data_vec.empty());
#endif
  for ( size_t i = hook_data_vec.size(); i > 0; --i )
  {
    const hook_data_t &hd = hook_data_vec[i-1];
    idapython_unhook_from_notification_point(hd.type, hd.cb, hd.ud);
  }
}

//-------------------------------------------------------------------------
// Plugin init routine
int idaapi init(void)
{
  if ( IDAPython_Init() )
    return PLUGIN_KEEP;
  else
    return PLUGIN_SKIP;
}

//-------------------------------------------------------------------------
// Plugin term routine
void idaapi term(void)
{
  IDAPython_Term();
}

//-------------------------------------------------------------------------
// Plugin hotkey entry point
bool idaapi run(size_t arg)
{
  try
  {
    switch ( arg )
    {
      case IDAPYTHON_RUNSTATEMENT:
        IDAPython_RunStatement();
        break;
      case IDAPYTHON_ENABLE_EXTLANG:
        enable_extlang_python(true);
        break;
      case IDAPYTHON_DISABLE_EXTLANG:
        enable_extlang_python(false);
        break;
      default:
        warning("IDAPython: unknown plugin argument %d", int(arg));
        break;
    }
  }
  catch(...)    //lint !e1766 without preceding catch clause
  {
    warning("Exception in Python interpreter. Reloading...");
    IDAPython_Term();
    IDAPython_Init();
  }
  return true;
}

//-------------------------------------------------------------------------
// PLUGIN DESCRIPTION BLOCK
//-------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_FIX | PLUGIN_HIDE, // plugin flags
  init,          // initialize
  term,          // terminate. this pointer may be NULL.
  run,           // invoke plugin
  S_IDAPYTHON,   // long comment about the plugin
                 // it could appear in the status line
                 // or as a hint
  // multiline help about the plugin
  "IDA Python Plugin\n",
  // the preferred short name of the plugin
  S_IDAPYTHON,
  // the preferred hotkey to run the plugin
  NULL
};
