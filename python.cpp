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

#ifdef __LINUX__
#include <dlfcn.h>
#endif
#ifdef __MAC__
#include <mach-o/dyld.h>
#endif
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <diskio.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <ida_highlighter.hpp>

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
static const char S_IDC_RUNPYTHON_STATEMENT[] =  "RunPythonStatement";
static const char S_IDAPYTHON_DATA_NODE[] =      "IDAPython_Data";

//-------------------------------------------------------------------------
// Types

//
enum script_run_when
{
  run_on_db_open = 0,  // run script after opening database (default)
  run_on_ui_ready = 1, // run script when UI is ready
  run_on_init = 2,     // run script immediately on plugin load (shortly after IDA starts)
};

//-------------------------------------------------------------------------
// Global variables
static bool g_instance_initialized = false; // This instance of the plugin is the one
                                            // that initialized the python interpreter.
static int  g_run_when = -1;
static char g_run_script[QMAXPATH];
static char g_idapython_dir[QMAXPATH];

//-------------------------------------------------------------------------
// Prototypes and forward declarations

// // Alias to SWIG_Init
// //lint -esym(526,init_idaapi) not defined
// extern "C" void init_idaapi(void);

// Plugin run() callback
void idaapi run(int arg);

//-------------------------------------------------------------------------
// This is a simple tracing code for debugging purposes.
// It might evolve into a tracing facility for user scripts.

//#define ENABLE_PYTHON_PROFILING
#ifdef ENABLE_PYTHON_PROFILING
#include "compile.h"
#include "frameobject.h"

int tracefunc(PyObject *obj, _frame *frame, int what, PyObject *arg)
{
    PyObject *str;

    /* Catch line change events. */
    /* Print the filename and line number */
    if ( what == PyTrace_LINE )
    {
        str = PyObject_Str(frame->f_code->co_filename);
        if ( str )
        {
            msg("PROFILING: %s:%d\n", PyString_AsString(str), frame->f_lineno);
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
static bool g_use_local_python = false;
static bool g_autoimport_compat_idaapi = true;

// Allowing the user to interrupt a script is not entirely trivial.
// Imagine the following script, that is run in an IDB that uses
// an IDAPython processor module (important!) :
// ---
// while True:
//     gen_disasm_text(ea, ea + 4, dtext, False)
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
  exec_entry_t() { etime = time(NULL); }
};
DECLARE_TYPE_AS_MOVABLE(exec_entry_t);
typedef qvector<exec_entry_t> exec_entries_t;

//-------------------------------------------------------------------------
struct execution_t
{
  exec_entries_t entries;
  int timeout;
  uint32 steps_before_action;
  bool waitdialog_shown;

  execution_t()
    : timeout(2),
      steps_before_action(0),
      waitdialog_shown(false)
  {
    reset_steps();
  }
  void reset_steps();
  void push();
  void pop();
  bool can_interrupt_current(time_t now) const;
  void stop_tracking();
  void sync_to_present_time();
  void maybe_hide_waitdialog();
  static int on_trace(PyObject *obj, _frame *frame, int what, PyObject *arg);
};
static execution_t execution;

//#define LOG_EXEC 1
#ifdef LOG_EXEC
#define LEXEC(Format, ...) msg("IDAPython exec: " Format, __VA_ARGS__)
#else
#define LEXEC(Format, ...)
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
  //     gen_disasm_text(ea, ea + 4, dtext, False)
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
    PyEval_SetTrace(execution_t::on_trace, NULL);
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
  PyEval_SetTrace(NULL, NULL);
  maybe_hide_waitdialog();
}

//-------------------------------------------------------------------------
void execution_t::sync_to_present_time()
{
  time_t now = time(NULL);
  for ( size_t i = 0, n = entries.size(); i < n; ++i )
    entries[i].etime = now;
  maybe_hide_waitdialog();
}

//-------------------------------------------------------------------------
void execution_t::maybe_hide_waitdialog()
{
  if ( waitdialog_shown )
  {
    hide_wait_box();
    waitdialog_shown = false;
  }
}

//-------------------------------------------------------------------------
bool execution_t::can_interrupt_current(time_t now) const
{
  LEXEC("can_interrupt_current(): nentries: %d\n", int(entries.size()));
  if ( entries.empty() || timeout <= 0 )
    return false;
  const exec_entry_t &last = entries.back();
  bool can = (now - last.etime) > timeout;
  LEXEC("can_interrupt_current(): last: %d, now: %d (-> %d)\n",
        int(last.etime), int(now), can);
  return can;
}

//------------------------------------------------------------------------
int execution_t::on_trace(PyObject *obj, _frame *frame, int what, PyObject *arg)
{
  LEXEC("on_trace() (steps=%d, nentries=%d)\n",
      int(execution.steps_before_action), int(execution.entries.size()));
  // we don't want to query for time at every trace event
  if ( execution.steps_before_action-- > 0 )
    return 0;

  execution.reset_steps();
  time_t now = time(NULL);
  LEXEC("on_trace()::now: %d\n", int(now));
  bool can_interrupt = execution.can_interrupt_current(now);
  if ( can_interrupt )
  {
    LEXEC("on_trace()::can_interrupt. Waitdialog shown? %d\n",
          int(execution.waitdialog_shown));
    if ( execution.waitdialog_shown )
    {
      if ( wasBreak() )
      {
        LEXEC("on_trace()::INTERRUPTING\n");
        PyErr_SetString(PyExc_KeyboardInterrupt, "User interrupted");
        return -1;
      }
    }
    else
    {
      LEXEC("on_trace()::showing wait dialog\n");
      show_wait_box("Running Python script");
      execution.waitdialog_shown = true;
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
//lint -esym(1788, new_execution_t) is referenced only by its constructor or destructor
struct new_execution_t
{
  bool created;
  new_execution_t()
  {
    created = g_ui_ready && execution.timeout > 0;
    if ( created )
    {
      PYW_GIL_CHECK_LOCKED_SCOPE();
      execution.push();
    }
  }
  ~new_execution_t()
  {
    if ( created )
    {
      PYW_GIL_CHECK_LOCKED_SCOPE();
      execution.pop();
    }
  }
};

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
      char *errbuf,
      size_t errbufsize,
      bool clear_error = true)
{
  if ( errbufsize > 0 && errbuf != NULL )
    errbuf[0] = '\0';

  // No exception?
  if ( !PyErr_Occurred() )
    return;

  qstring s;
  if ( PyW_GetError(&s, clear_error) && errbuf != NULL )
    qstrncpy(errbuf, s.c_str(), errbufsize);
}

//------------------------------------------------------------------------
// Helper function to get globals for the __main__ module
// Note: The references are borrowed. No need to free them.
static PyObject *GetMainGlobals()
{
  PyObject *module = PyImport_AddModule(S_MAIN);
  return module == NULL ? NULL : PyModule_GetDict(module);
}

//------------------------------------------------------------------------
static void PythonEvalOrExec(
    const char *str,
    const char *filename = "<string>")
{
  // Compile as an expression
  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyCompilerFlags cf = {0};
  newref_t py_code(Py_CompileStringFlags(str, filename, Py_eval_input, &cf));
  if ( py_code == NULL || PyErr_Occurred() )
  {
    // Not an expression?
    PyErr_Clear();

    // Run as a string
    PyRun_SimpleString(str);
  }
  else
  {
    PyObject *py_globals = GetMainGlobals();
    newref_t py_result(
            PyEval_EvalCode(
                    (PyCodeObject *) py_code.o,
                    py_globals,
                    py_globals));

    if ( py_result == NULL || PyErr_Occurred() )
    {
      PyErr_Print();
    }
    else
    {
      if ( py_result.o != Py_None )
      {
        bool ok = false;
        if ( PyUnicode_Check(py_result.o) )
        {
          newref_t py_result_utf8(PyUnicode_AsUTF8String(py_result.o));
          ok = py_result_utf8 != NULL;
          if ( ok )
            umsg("%s\n", PyString_AS_STRING(py_result_utf8.o));
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

//------------------------------------------------------------------------
// Executes a simple string
static bool idaapi IDAPython_extlang_run_statements(
  const char *str,
  char *errbuf,
  size_t errbufsize)
{
  PYW_GIL_GET;
  PyObject *globals = GetMainGlobals();
  bool ok;
  if ( globals == NULL )
  {
    ok = false;
  }
  else
  {
    errbuf[0] = '\0';
    PyErr_Clear();
    {
      new_execution_t exec;
      newref_t result(PyRun_String(
                              str,
                              Py_file_input,
                              globals,
                              globals));
      ok = result != NULL && !PyErr_Occurred();
      if ( !ok )
        handle_python_error(errbuf, errbufsize);
    }
  }
  if ( !ok && errbuf[0] == '\0' )
    qstrncpy(errbuf, "internal error", errbufsize);
  return ok;
}

//------------------------------------------------------------------------
// Simple Python statement runner function for IDC
static const char idc_runpythonstatement_args[] = { VT_STR2, 0 };
static error_t idaapi idc_runpythonstatement(
      idc_value_t *argv,
      idc_value_t *res)
{
  char errbuf[MAXSTR];
  bool ok = IDAPython_extlang_run_statements(argv[0].c_str(), errbuf, sizeof(errbuf));

  if ( ok )
    res->set_long(0);
  else
    res->set_string(errbuf);

  return eOk;
}

//--------------------------------------------------------------------------
static const cfgopt_t opts[] =
{
  cfgopt_t("SCRIPT_TIMEOUT", &execution.timeout, 0, INT_MAX),
  cfgopt_t("ALERT_AUTO_SCRIPTS", &g_alert_auto_scripts, true),
  cfgopt_t("REMOVE_CWD_SYS_PATH", &g_remove_cwd_sys_path, true),
  cfgopt_t("AUTOIMPORT_COMPAT_IDAAPI", &g_autoimport_compat_idaapi, true),
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

  // on linux, PyQt needs to drop python/lib/python2.7/lib-dynload/sip.so,
  // thus we can't rely on the mere presence of 'lib'. However, we know
  // the bundled python drops python/lib/python27.zip. Let's look for that.
#ifdef __LINUX__
  qmakepath(filepath, sizeof(filepath), g_idapython_dir, "lib", "python27.zip", NULL);
  if ( qfileexist(filepath) )
  {
    deb(IDA_DEBUG_PLUGIN, "Found \"%s\"; assuming local Python.\n", filepath);
    g_use_local_python = true;
  }
#endif // __LINUX__

  return true;
}

//-------------------------------------------------------------------------
// This function will execute a script in the main module context
// It does not use 'import', thus the executed script will not yield a new module name
// Caller of this function should call handle_python_error() to clear the exception and print the error
static int PyRunFile(const char *FileName)
{
#ifdef __NT__
  // if the current disk has no space (sic, the current directory, not the one
  // with the input file), PyRun_File() will die with a cryptic message that
  // C runtime library could not be loaded. So we check the disk space before
  // calling it.
  char curdir[QMAXPATH];
  // check if the current directory is accessible. if not, qgetcwd won't return
  qgetcwd(curdir, sizeof(curdir));
  if ( getdspace(curdir) == 0 )
  {
    warning("No free disk space on %s, python will not be available", curdir);
    return 0;
  }
#endif

  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyObject *file_obj = PyFile_FromString((char*)FileName, "r"); //lint !e605
  PyObject *globals = GetMainGlobals();
  if ( globals == NULL || file_obj == NULL )
  {
    Py_XDECREF(file_obj);
    return 0;
  }
  PyErr_Clear();

  PyObject *result = PyRun_File(
        PyFile_AsFile(file_obj),
        FileName,
        Py_file_input,
        globals,
        globals);
  Py_XDECREF(file_obj);
  int rc = result != NULL && !PyErr_Occurred();
  Py_XDECREF(result);
  return rc;
}

//-------------------------------------------------------------------------
// Execute Python statement(s) from an editor window
void IDAPython_RunStatement(void)
{
  char statement[16 * MAXSTR];
  netnode history;

  // Get the existing or create a new netnode in the database
  history.create(S_IDAPYTHON_DATA_NODE);

  // Fetch the previous statement
  size_t statement_size = sizeof(statement);

  if ( history.getblob(statement, &statement_size, 0, 'A') == NULL )
    statement[0] = '\0';

  if ( asktext(sizeof(statement), statement, statement, "ACCEPT TABS\nEnter Python expressions") != NULL )
  {
    {
      new_execution_t exec;
      PyRun_SimpleString(statement);
    }

    // Store the statement to the database
    history.setblob(statement, strlen(statement) + 1, 0, 'A');
  }
}

//-------------------------------------------------------------------------
// Convert return value from Python to IDC or report about an error.
// This function also decrements the reference "result" (python variable)
static bool return_python_result(
  idc_value_t *idc_result,
  const ref_t &py_result,
  char *errbuf,
  size_t errbufsize)
{
  if ( errbufsize > 0 )
    errbuf[0] = '\0';

  if ( py_result == NULL )
  {
    handle_python_error(errbuf, errbufsize);
    return false;
  }

  int cvt = CIP_OK;
  if ( idc_result != NULL )
  {
    idc_result->clear();
    cvt = pyvar_to_idcvar(py_result, idc_result);
    if ( cvt < CIP_OK )
      qsnprintf(errbuf, errbufsize, "ERROR: bad return value");
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
        char *errbuf,
        size_t errbufsz,
        const char *idaapi_script = S_IDAAPI_EXECSCRIPT,
        idc_value_t *second_res = NULL,
        bool want_tuple = false)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ref_t py_execscript(get_idaapi_attr(idaapi_script));
  if ( py_execscript == NULL )
  {
    qsnprintf(errbuf, errbufsz, "Could not find %s.%s ?!", S_IDA_IDAAPI_MODNAME, idaapi_script);
    return false;
  }

  char script[MAXSTR];
  qstrncpy(script, FileName, sizeof(script));
  strrpl(script, '\\', '/');

  newref_t py_script(PyString_FromString(script));
  borref_t py_false(Py_False);
  newref_t py_ret(PyObject_CallFunctionObjArgs(
    py_execscript.o,
    py_script.o,
    GetMainGlobals(),
    py_false.o,
    NULL));

  // Failure at this point means the script was interrupted
  bool interrupted = false;
  qstring err;
  if ( PyW_GetError(&err) || py_ret == NULL )
  {
    PyErr_Clear();
    if ( err.empty() )
      qstrncpy(errbuf, "Script interrupted", errbufsz);
    else
      qstrncpy(errbuf, err.c_str(), errbufsz);
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

    if ( ret_o == Py_None )
    {
      if ( want_tuple )
      {
        borref_t ret2_o(PyTuple_GetItem(py_ret.o, 1));
        ok = return_python_result(second_res, ret2_o, errbuf, errbufsz);
      }
      else
      {
        ok = true;
      }
    }
    else if ( PyString_Check(ret_o) )
    {
      qstrncpy(errbuf, PyString_AsString(ret_o), errbufsz);
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
  char errbuf[MAXSTR];
  bool ok;
  {
    new_execution_t exec;
    ok = IDAPython_ExecFile(script, errbuf, sizeof(errbuf));
  }
  if ( !ok )
    warning("IDAPython: error executing '%s':\n%s", script, errbuf);

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
  const char *p = strchr(full_name, '.');
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
bool idaapi IDAPython_extlang_run(
  const char *name,
  int nargs,
  const idc_value_t args[],
  idc_value_t *result,
  char *errbuf,
  size_t errbufsize)
{
  PYW_GIL_GET;
  // Try to extract module name (if any) from the funcname
  char modname[MAXSTR] = {0};
  char funcname[MAXSTR] = {0};
  bool imported_module = parse_py_modname(name, modname, funcname, MAXSTR);

  bool ok = true;
  PyObject *module = NULL;
  ref_vec_t pargs;
  do
  {
    // Convert arguments to python
    ok = pyw_convert_idc_args(args, nargs, pargs, false, errbuf, errbufsize);
    if ( !ok )
      break;

    if ( imported_module )
    {
      module = PyImport_ImportModule(modname);
    }
    else
    {
      module = PyImport_AddModule(S_MAIN);
      QASSERT(30156, module != NULL);
    }

    PyObject *globals = PyModule_GetDict(module);
    QASSERT(30157, globals != NULL);

    PyObject *func = PyDict_GetItemString(globals, funcname);
    if ( func == NULL )
    {
      qsnprintf(errbuf, errbufsize, "undefined function %s", name);
      ok = false;
      break;
    }

    borref_t code(PyFunction_GetCode(func));
    qvector<PyObject*> pargs_ptrs;
    pargs.to_pyobject_pointers(&pargs_ptrs);
    newref_t py_res(PyEval_EvalCodeEx(
                            (PyCodeObject*) code.o,
                            globals, NULL,
                            pargs_ptrs.begin(),
                            nargs,
                            NULL, 0, NULL, 0, NULL));
    ok = return_python_result(result, py_res, errbuf, errbufsize);
  } while ( false );

  if ( imported_module )
    Py_XDECREF(module);
  return ok;
}

//-------------------------------------------------------------------------
static void wrap_in_function(qstring *out, const qstring &body, const char *name)
{
  out->sprnt("def %s():\n", name);
  // dont copy trailing whitespace
  int i = body.length()-1;
  while ( i >= 0 && qisspace(body.at(i)) )
    i--;
  out->append(body.substr(0, i+1));
  out->replace("\n", "\n    ");
}

//-------------------------------------------------------------------------
// Compile callback for Python external language evaluator
bool idaapi IDAPython_extlang_compile(
  const char *name,
  ea_t /*current_ea*/,
  const char *expr,
  char *errbuf,
  size_t errbufsize)
{
  PYW_GIL_GET;
  PyObject *globals = GetMainGlobals();
  bool is_func = false;

  PyCodeObject *code = (PyCodeObject *)Py_CompileString(expr, "<string>", Py_eval_input);
  if ( code == NULL )
  {
    // try compiling as a list of statements
    // wrap them into a function
    handle_python_error(errbuf, errbufsize);
    qstring func;
    wrap_in_function(&func, expr, name);
    code = (PyCodeObject *)Py_CompileString(func.c_str(), "<string>", Py_file_input);
    if ( code == NULL )
    {
      handle_python_error(errbuf, errbufsize);
      return false;
    }
    is_func = true;
  }

  // Set the desired function name
  Py_XDECREF(code->co_name);
  code->co_name = PyString_FromString(name);

  // Create a function out of code
  PyObject *func = PyFunction_New((PyObject *)code, globals);

  if ( func == NULL )
  {
ERR:
    handle_python_error(errbuf, errbufsize);
    Py_XDECREF(code);
    return false;
  }

  int err = PyDict_SetItemString(globals, name, func);
  Py_XDECREF(func);

  if ( err )
    goto ERR;

  if ( is_func )
  {
    const idc_value_t args;
    idc_value_t result;
    return IDAPython_extlang_run(name, 0, &args, &result, errbuf, errbufsize);
  }
  return true;
}

//-------------------------------------------------------------------------
// Compile callback for Python external language evaluator
bool idaapi IDAPython_extlang_compile_file(
        const char *filename,
        char *errbuf,
        size_t errbufsize)
{
  PYW_GIL_GET;
  new_execution_t exec;
  return IDAPython_ExecFile(filename, errbuf, errbufsize);
}

//-------------------------------------------------------------------------
// Load processor module callback for Python external language evaluator
static bool idaapi IDAPython_extlang_loadprocmod(
        const char *filename,
        idc_value_t *procobj,
        char *errbuf,
        size_t errbufsize)
{
  PYW_GIL_GET;
  bool ok;
  {
    new_execution_t exec;
    ok = IDAPython_ExecFile(filename, errbuf, errbufsize, S_IDAAPI_LOADPROCMOD, procobj, true);
  }
  if ( ok && procobj->is_zero() )
  {
    errbuf[0] = '\0';
    ok = false;
  }
  return ok;
}

//-------------------------------------------------------------------------
// Unload processor module callback for Python external language evaluator
static bool idaapi IDAPython_extlang_unloadprocmod(
  const char *filename,
  char *errbuf,
  size_t errbufsize)
{
  PYW_GIL_GET;
  new_execution_t exec;
  return IDAPython_ExecFile(filename, errbuf, errbufsize, S_IDAAPI_UNLOADPROCMOD);
}

//-------------------------------------------------------------------------
// Create an object instance
bool idaapi IDAPython_extlang_create_object(
  const char *name,       // in: object class name
  int nargs,              // in: number of input arguments
  const idc_value_t args[], // in: input arguments
  idc_value_t *result,    // out: created object or exception
  char *errbuf,           // out: error message if evaluation fails
  size_t errbufsize)     // in: size of the error buffer
{
  PYW_GIL_GET;
  bool ok = false;
  ref_vec_t pargs;
  do
  {
    // Parse the object name (to get the module and class name)
    char modname[MAXSTR] = {0};
    char clsname[MAXSTR] = {0};
    parse_py_modname(name, modname, clsname, MAXSTR);

    // Get a reference to the module
    ref_t py_mod(PyW_TryImportModule(modname));
    if ( py_mod == NULL )
    {
      qsnprintf(errbuf, errbufsize, "Could not import module '%s'!", modname);
      break;
    }

    // Get the class reference
    ref_t py_cls(PyW_TryGetAttrString(py_mod.o, clsname));
    if ( py_cls == NULL )
    {
      qsnprintf(errbuf, errbufsize, "Could not find class type '%s'!", clsname);
      break;
    }

    // Error during conversion?
    ok = pyw_convert_idc_args(args, nargs, pargs, true, errbuf, errbufsize);
    if ( !ok )
      break;

    // Call the constructor
    newref_t py_res(PyObject_CallObject(py_cls.o, pargs.empty() ? NULL : pargs[0].o));
    ok = return_python_result(result, py_res, errbuf, errbufsize);
  } while ( false );

  return ok;
}

//-------------------------------------------------------------------------
// Returns the attribute value of a given object from the global scope
bool idaapi IDAPython_extlang_get_attr(
  const idc_value_t *obj, // in: object (may be NULL)
  const char *attr,       // in: attribute name
  idc_value_t *result)
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
      if ( obj->vtype == VT_STR2 )
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
      const char *clsname = PyString_AsString(string.o);
      if ( clsname == NULL )
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
bool idaapi IDAPython_extlang_set_attr(
  idc_value_t *obj,       // in: object name (may be NULL)
  const char *attr,       // in: attribute name
  idc_value_t *value)
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
      if ( obj->vtype == VT_STR2 )
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
    int cvt = idcvar_to_pyvar(*value, &py_var);
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
bool idaapi IDAPython_extlang_calcexpr(
  ea_t /*current_ea*/,
  const char *expr,
  idc_value_t *rv,
  char *errbuf,
  size_t errbufsize)
{
  PYW_GIL_GET;
  PyObject *globals = GetMainGlobals();
  bool ok = globals != NULL;
  ref_t result;
  if ( ok )
  {
    {
      new_execution_t exec;
      result = newref_t(PyRun_String(expr, Py_eval_input, globals, globals));
    }
    ok = return_python_result(rv, result, errbuf, errbufsize);
  }
  return ok;
}

//-------------------------------------------------------------------------
bool idaapi IDAPython_extlang_call_method(
  const idc_value_t *idc_obj,
  const char *method_name,
  int nargs,
  const idc_value_t args[],
  idc_value_t *result,
  char *errbuf,
  size_t errbufsize)
{
  PYW_GIL_GET;
  // Check for unsupported usage of call_method.
  // Mainly a method call requires an object and a method.
  if ( (idc_obj == NULL && method_name == NULL) || (idc_obj != NULL && method_name == NULL) )
  {
    qstrncpy(errbuf, "call_method does not support this operation", errbufsize);
    return false;
  }
  // Behave like run()
  else if ( idc_obj == NULL && method_name != NULL )
  {
    new_execution_t exec;
    return IDAPython_extlang_run(method_name, nargs, args, result, errbuf, errbufsize);
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
      qstrncpy(errbuf, "Failed to convert input object to Python value", errbufsize);
      break;
    }

    ref_t py_method(PyW_TryGetAttrString(py_obj.o, method_name));
    if ( py_method == NULL || !PyCallable_Check(py_method.o) )
    {
      qsnprintf(errbuf, errbufsize, "The input object does not have a callable method called '%s'", method_name);
      break;
    }

    // Convert arguments to python objects
    ok = pyw_convert_idc_args(args, nargs, pargs, true, errbuf, errbufsize);
    if ( !ok )
      break;

    {
      new_execution_t exec;
      newref_t py_res(PyObject_CallObject(py_method.o, pargs.empty() ? NULL : pargs[0].o));
      ok = return_python_result(result, py_res, errbuf, errbufsize);
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

const extlang_t extlang_python =
{
    sizeof(extlang_t),
    0,
    "Python",
    IDAPython_extlang_compile,
    IDAPython_extlang_run,
    IDAPython_extlang_calcexpr,
    IDAPython_extlang_compile_file,
    "py",
    IDAPython_extlang_create_object,
    IDAPython_extlang_get_attr,
    IDAPython_extlang_set_attr,
    IDAPython_extlang_call_method,
    IDAPython_extlang_run_statements,
    IDAPython_extlang_loadprocmod,
    IDAPython_extlang_unloadprocmod,
    &python_highlighter
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
bool idaapi IDAPYthon_cli_complete_line(
    qstring *completion,
    const char *prefix,
    int n,
    const char *line,
    int x)
{
  PYW_GIL_GET;

  ref_t py_complete(get_idaapi_attr(S_IDAAPI_COMPLETION));
  if ( py_complete == NULL )
    return false;

  newref_t py_ret(PyObject_CallFunction(py_complete.o, "sisi", prefix, n, line, x)); //lint !e605

  // Swallow the error
  PyW_GetError(completion);

  bool ok = py_ret != NULL && PyString_Check(py_ret.o);
  if ( ok )
    *completion = PyString_AS_STRING(py_ret.o);
  return ok;
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
    IDAPYthon_cli_complete_line,
    NULL
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

  // No options?
  if ( options == NULL )
    return;

  // User specified 'when' parameter?
  const char *p = strchr(options, ';');
  if ( p == NULL )
  {
    g_run_when = run_on_db_open;
    p = options;
  }
  else
  {
    g_run_when = atoi(options);
    ++p;
  }
  qstrncpy(g_run_script, p, sizeof(g_run_script));
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
    for ( int i=1; VarGetAttr(idc_args, attr_name, &attr) == eOk; i++ )
    {
      PyList_Insert(py_args.o, i, PyString_FromString(attr.c_str()));
      qsnprintf(attr_name, sizeof(attr_name), "%d", i);
    }
  }

  // Get reference to the IDC module (it is imported by init.py)
  ref_t py_mod(PyW_TryImportModule(S_IDC_MODNAME));
  if ( py_mod != NULL )
    PyObject_SetAttrString(py_mod.o, S_IDC_ARGS_VARNAME, py_args.o);
}

//------------------------------------------------------------------------
//lint -esym(715,va) Symbol not referenced
static int idaapi on_ui_notification(void *, int code, va_list)
{
  switch ( code )
  {
    case ui_term:
      {
        PYW_GIL_GET; // This hook gets called from the kernel. Ensure we hold the GIL.
        // Let's make sure there are no non-Free()d forms.
        free_compiled_form_instances();
      }
      break;

    case ui_ready_to_run:
      {
        PYW_GIL_GET; // See above
        g_ui_ready = true;
        PyRun_SimpleString("print_banner()");
        if ( g_run_when == run_on_ui_ready )
          RunScript(g_run_script);
      }
      break;

    case ui_database_inited:
      {
        PYW_GIL_GET; // See above
        convert_idc_args();
        if ( g_run_when == run_on_db_open )
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
static int idaapi on_idp_notification(void *, int code, va_list)
{
  switch ( code )
  {
    case processor_t::closebase:
      // The til machinery is about to garbage-collect: We must go
      // through all the tinfo_t objects that are embedded in SWIG wrappers,
      // (i.e., that were created from Python) and clear those.
      til_clear_python_tinfo_t_instances();
      // Same thing for live python timers
      clear_python_timer_instances();
      break;
  }
  return 0;
}

#ifdef _DEBUG
//------------------------------------------------------------------------
// extern int PyThread_acquire_lock(PyThread_type_lock lock, int waitflag);
extern PyThreadState *_PyThreadState_Current;
static int idaapi ui_debug_handler_cb(void *, int code, va_list)
{
  // This hook gets called from the kernel, but its very point is to
  // make sure that we don't hold the GIL. Thus: No PYW_GIL_GET here!
  switch ( code )
  {
    case debug_assert_thread_waitready:
      // We will *always* be in a non-main thread when this is called.
      if ( _PyThreadState_Current != NULL )
      {
        PyThreadState *tcur = PyGILState_GetThisThreadState();
        if ( tcur == _PyThreadState_Current )
        {
          // This thread is the '_PyThreadState_Current'; i.e., it holds the lock.
          // We're likely to end up in a deadlock.
          BPT;
        }
      }
      break;
    default:
      break;
  }
  return 0;
}
#endif

//-------------------------------------------------------------------------
// - remove current directory (empty entry) from the sys.path
// - add idadir("python")
static void prepare_sys_path()
{
  char buf[QMAXPATH];
  qstrncpy(buf, Py_GetPath(), sizeof(buf));
  char *ctx;
  qstring newpath;
  for ( char *d0 = qstrtok(buf, DELIMITER, &ctx);
        d0 != NULL;
        d0 = qstrtok(NULL, DELIMITER, &ctx) )
  {
    if ( d0[0] == '\0' )
      // skip empty entry
      continue;

    if ( !newpath.empty() )
      newpath.append(DELIMITER);
    newpath.append(d0);
  }
  if ( !newpath.empty() )
    newpath.append(DELIMITER);
  newpath.append(idadir("python"));
  PySys_SetPath(newpath.begin());
}


//-------------------------------------------------------------------------
// we have to do it ourselves because Python 2.7 calls exit() if importing site fails
static bool initsite(void)
{
  PyObject *m;
  m = PyImport_ImportModule("site");
  if ( m == NULL )
  {
    PyErr_Print();
    Py_Finalize();
    return false;
  }
  else
  {
    Py_DECREF(m);
  }
  return true;
}

//-------------------------------------------------------------------------
static void init_ida_modules()
{
  // char buf[QMAXPATH];
  // // IDA_MODULES must be passed as a define
  // qstrncpy(buf, IDA_MODULES, sizeof(buf));
  // char *ctx;
  // for ( char *module = qstrtok(buf, ",", &ctx);
  //       module != NULL;
  //       module = qstrtok(NULL, DELIMITER, &ctx) )
  // {
  //   deb(IDA_DEBUG_PLUGIN, "Initializing \"ida_%s\"\n", module);
  // }

  // Load the 'ida_idaapi' module, that contains some important bits of code
  // ref_t ida_idaapi(PyW_TryImportModule(S_PY_IDA_IDAAPI_MODNAME));

  // ref_t sys(PyW_TryImportModule("sys"));
}

//-------------------------------------------------------------------------
// Initialize the Python environment
bool IDAPython_Init(void)
{
  if ( Py_IsInitialized() != 0 )
    return true;

  // Form the absolute path to IDA\python folder
  qstrncpy(g_idapython_dir, idadir(PYTHON_DIR_NAME), sizeof(g_idapython_dir));

  // Check for the presence of essential files
  if ( !check_python_dir() )
    return false;

  char tmp[QMAXPATH];
#ifdef __LINUX__
  // Export symbols from libpython to resolve imported module deps
  // use the standard soname: libpython2.7.so.1.0
#define PYLIB "libpython" QSTRINGIZE(PY_MAJOR_VERSION) "." QSTRINGIZE(PY_MINOR_VERSION) ".so.1.0"
  if ( !dlopen(PYLIB, RTLD_NOLOAD | RTLD_GLOBAL | RTLD_LAZY) )
  {
    warning("IDAPython dlopen(" PYLIB ") error: %s", dlerror());
    return false;
  }
#endif

#ifdef __MAC__
  // We should set python home to the module's path, otherwise it can pick up stray modules from $PATH
  NSModule pythonModule = NSModuleForSymbol(NSLookupAndBindSymbol("_Py_InitializeEx"));
  // Use dylib functions to find out where the framework was loaded from
  const char *buf = (char *)NSLibraryNameForModule(pythonModule);
  if ( buf != NULL )
  {
    // The path will be something like:
    // /System/Library/Frameworks/Python.framework/Versions/2.5/Python
    // We need to strip the last part
    // use static buffer because Py_SetPythonHome() just stores a pointer
    static char pyhomepath[MAXSTR];
    qstrncpy(pyhomepath, buf, MAXSTR);
    char * lastslash = strrchr(pyhomepath, '/');
    if ( lastslash != NULL )
    {
      *lastslash = 0;
      Py_SetPythonHome(pyhomepath);
    }
  }
#endif

  // Read configuration value
  read_config_file("python.cfg", opts, qnumber(opts));
  if ( g_alert_auto_scripts )
  {
    if ( pywraps_check_autoscripts(tmp, sizeof(tmp))
      && askyn_c(0, "HIDECANCEL\nTITLE IDAPython\nThe script '%s' was found in the current directory and will be automatically executed by Python.\n\n"
                    "Do you want to continue loading IDAPython?", tmp) <= 0 )
    {
      return false;
    }
  }

  if ( g_use_local_python )
  {
    // Set the program name:
    // "This is used by Py_GetPath() and some other functions below to find the
    //  Python run-time libraries relative to the interpreter executable".
    // <https://docs.python.org/2/c-api/init.html#c.Py_SetProgramName>
    //
    // Note:
    // "The argument should point to a zero-terminated character string
    //  in static storage whose contents will not change for the duration
    //  of the program's execution"
    static qstring pname = idadir("");
    Py_SetProgramName(pname.begin());
    Py_SetPythonHome(g_idapython_dir);
  }

  // don't import "site" right now
  Py_NoSiteFlag = 1;

  // Start the interpreter
  Py_InitializeEx(0 /* Don't catch SIGPIPE, SIGXFZ, SIGXFSZ & SIGINT signals */);

  if ( !Py_IsInitialized() )
  {
    warning("IDAPython: Py_InitializeEx() failed");
    return false;
  }

  // remove current directory
  prepare_sys_path();

  // import "site"
  if ( !g_use_local_python && !initsite() )
  {
    warning("IDAPython: importing \"site\" failed");
    return false;
  }

  // Enable multi-threading support
  if ( !PyEval_ThreadsInitialized() )
    PyEval_InitThreads();

  init_ida_modules();

#ifdef Py_DEBUG
  msg("HexraysPython: Python compiled with DEBUG enabled.\n");
#endif

  // Set IDAPYTHON_VERSION in Python
  qsnprintf(
          tmp,
          sizeof(tmp),
          "IDAPYTHON_VERSION=(%d, %d, %d, '%s', %d)\n"
          "IDAPYTHON_REMOVE_CWD_SYS_PATH = %s\n"
          "IDAPYTHON_DYNLOAD_BASE = r\"%s\"\n"
          "IDAPYTHON_DYNLOAD_RELPATH = \"ida_%d\"\n"
          "IDAPYTHON_COMPAT_AUTOIMPORT_MODULES = %s\n",
          VER_MAJOR,
          VER_MINOR,
          VER_PATCH,
          VER_STATUS,
          VER_SERIAL,
          g_remove_cwd_sys_path ? "True" : "False",
          idadir(NULL),
#ifdef __EA64__
          64,
#else
          32,
#endif
          g_autoimport_compat_idaapi ? "True" : "False");
  PyRun_SimpleString(tmp);

  // Install extlang. Needs to be done before running init.py
  // in case it's calling idaapi.enable_extlang_python(1)
  install_extlang(&extlang_python);

  // Execute init.py (for Python side initialization)
  qmakepath(tmp, MAXSTR, g_idapython_dir, S_INIT_PY, NULL);
  if ( !PyRunFile(tmp) )
  {
    // Try to fetch a one line error string. We must do it before printing
    // the traceback information. Make sure that the exception is not cleared
    handle_python_error(tmp, sizeof(tmp), false);

    // Print the exception traceback
    PyRun_SimpleString("import traceback;traceback.print_exc();");

    warning("IDAPython: error executing " S_INIT_PY ":\n"
            "%s\n"
            "\n"
            "Refer to the message window to see the full error log.", tmp);
    remove_extlang(&extlang_python);
    return false;
  }

  // Init pywraps and notify_when
  if ( !init_pywraps() || !pywraps_nw_init() )
  {
    warning("IDAPython: init_pywraps() failed!");
    remove_extlang(&extlang_python);
    return false;
  }

#ifdef ENABLE_PYTHON_PROFILING
  PyEval_SetTrace(tracefunc, NULL);
#endif

  // Batch-mode operation:
  parse_plugin_options();

  // Register a RunPythonStatement() function for IDC
  set_idc_func_ex(
          S_IDC_RUNPYTHON_STATEMENT,
          idc_runpythonstatement,
          idc_runpythonstatement_args,
          0);

  // A script specified on the command line is run
  if ( g_run_when == run_on_init )
    RunScript(g_run_script);

#ifdef _DEBUG
  hook_to_notification_point(HT_UI, ui_debug_handler_cb, NULL);
#endif
  hook_to_notification_point(HT_UI, on_ui_notification, NULL);
  hook_to_notification_point(HT_IDP, on_idp_notification, NULL);

  // Enable the CLI by default
  enable_python_cli(true);

  pywraps_nw_notify(NW_INITIDA_SLOT);

  PyEval_ReleaseThread(PyThreadState_Get());

  g_instance_initialized = true;
  return true;
}

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

  unhook_from_notification_point(HT_IDP, on_idp_notification, NULL);
  unhook_from_notification_point(HT_UI, on_ui_notification, NULL);
#ifdef _DEBUG
  unhook_from_notification_point(HT_UI, ui_debug_handler_cb, NULL);
#endif

  // Notify about IDA closing
  pywraps_nw_notify(NW_TERMIDA_SLOT);

  // De-init notify_when
  pywraps_nw_term();

  // Remove the CLI
  enable_python_cli(false);

  // Remove the extlang
  remove_extlang(&extlang_python);

  // De-init pywraps
  deinit_pywraps();

  // Uninstall IDC function
  set_idc_func_ex(S_IDC_RUNPYTHON_STATEMENT, NULL, NULL, 0);

  // Shut the interpreter down
  Py_Finalize();
  g_instance_initialized = false;
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
void idaapi run(int arg)
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
      warning("IDAPython: unknown plugin argument %d", arg);
      break;
    }
  }
  catch(...)
  {
    warning("Exception in Python interpreter. Reloading...");
    IDAPython_Term();
    IDAPython_Init();
  }
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
