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

#ifdef WITH_HEXRAYS
#include <hexrays.hpp>
hexdsp_t *hexdsp = NULL;
#endif

#include "pywraps.hpp"

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
static const char S_MAIN[] =                     "__main__";
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

// Alias to SWIG_Init
//lint -esym(526,init_idaapi) not defined
extern "C" void init_idaapi(void);

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
static int    ninsns = 0;      // number of times trace function was called
static bool   box_displayed;  // has the wait box been displayed?
static time_t start_time;   // the start time of the execution
static int    script_timeout = 2;
static bool   g_ui_ready = false;
static bool   g_alert_auto_scripts = true;
static bool   g_remove_cwd_sys_path = false;
static bool   g_use_local_python    = false;

static void end_execution(void);
static void begin_execution(void);

//------------------------------------------------------------------------
// This callback is called on various interpreter events
static int break_check(PyObject *obj, _frame *frame, int what, PyObject *arg)
{
  if ( wasBreak() )
  {
    // User pressed Cancel in the waitbox; send KeyboardInterrupt exception
    PyErr_SetString(PyExc_KeyboardInterrupt, "User interrupted");
    return -1;
  }
  else if ( !box_displayed && ++ninsns > 10 )
  {
    // We check the timer once every 10 calls
    ninsns = 0;

    // Timeout disabled or elapsed?
    if ( script_timeout != 0 && (time(NULL) - start_time > script_timeout) )
    {
      box_displayed = true;
      show_wait_box("Running Python script");
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

//------------------------------------------------------------------------
static void reset_execution_time()
{
  start_time = time(NULL);
  ninsns = 0;
}

//------------------------------------------------------------------------
// Prepare for Python execution
static void begin_execution()
{
  if ( !g_ui_ready || script_timeout == 0 )
    return;

  PYW_GIL_CHECK_LOCKED_SCOPE();
  end_execution();
  reset_execution_time();
  PyEval_SetTrace(break_check, NULL);
}

//---------------------------------------------------------------------------
static void hide_script_waitbox()
{
  if ( box_displayed )
  {
    hide_wait_box();
    box_displayed = false;
  }
}

//------------------------------------------------------------------------
// Called after Python execution finishes
static void end_execution()
{
  hide_script_waitbox();
  PYW_GIL_CHECK_LOCKED_SCOPE();
#ifdef ENABLE_PYTHON_PROFILING
  PyEval_SetTrace(tracefunc, NULL);
#else
  PyEval_SetTrace(NULL, NULL);
#endif
}

//-------------------------------------------------------------------------
//lint -esym(714,disable_script_timeout) Symbol not referenced
void disable_script_timeout()
{
  // Clear timeout
  script_timeout = 0;

  // Uninstall the trace function and hide the waitbox (if it was shown)
  end_execution();
}

//-------------------------------------------------------------------------
//lint -esym(714,set_script_timeout) Symbol not referenced
int set_script_timeout(int timeout)
{
  // Update the timeout
  qswap(timeout, script_timeout);

  // Reset the execution time and hide the waitbox (so it is shown again after timeout elapses)
  reset_execution_time();
  hide_script_waitbox();

  return timeout;
}

//------------------------------------------------------------------------
// Return a formatted error or just print it to the console
static void handle_python_error(
      char *errbuf,
      size_t errbufsize,
      bool clear_error = true)
{
  if ( errbufsize > 0 )
    errbuf[0] = '\0';

  // No exception?
  if ( !PyErr_Occurred() )
    return;

  qstring s;
  if ( PyW_GetError(&s, clear_error) )
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
    begin_execution();
    newref_t result(PyRun_String(
                            str,
                            Py_file_input,
                            globals,
                            globals));
    end_execution();
    ok = result != NULL && !PyErr_Occurred();
    if ( !ok )
      handle_python_error(errbuf, errbufsize);
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
const char *idaapi set_python_options(
    const char *keyword,
    int value_type,
    const void *value)
{
  do
  {
    if ( value_type == IDPOPT_NUM )
    {
      if ( qstrcmp(keyword, "SCRIPT_TIMEOUT") == 0 )
      {
        script_timeout = int(*(uval_t *)value);
        break;
      }
      else if ( qstrcmp(keyword, "ALERT_AUTO_SCRIPTS") == 0 )
      {
        g_alert_auto_scripts = *(uval_t *)value != 0;
        break;
      }
      else if ( qstrcmp(keyword, "REMOVE_CWD_SYS_PATH") == 0 )
      {
        g_remove_cwd_sys_path = *(uval_t *)value != 0;
        break;
      }
      else if ( qstrcmp(keyword, "USE_LOCAL_PYTHON") == 0 )
      {
        g_use_local_python = *(uval_t *)value != 0;
        break;
      }
    }
    return IDPOPT_BADKEY;
  } while (false);
  return IDPOPT_OK;
}

//-------------------------------------------------------------------------
// Check for the presence of a file in IDADIR/python and complain on error
bool CheckScriptFiles()
{
  static const char *const script_files[] =
  {
    S_IDC_MODNAME ".py",
    S_INIT_PY,
    "idaapi.py",
    "idautils.py"
  };
  for ( size_t i=0; i<qnumber(script_files); i++ )
  {
    char filepath[QMAXPATH];
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
    begin_execution();
    PyRun_SimpleString(statement);
    end_execution();

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
    qsnprintf(errbuf, errbufsz, "Could not find idaapi.%s ?!", idaapi_script);
    return false;
  }

  char script[MAXSTR];
  qstrncpy(script, FileName, sizeof(script));
  strrpl(script, '\\', '/');

  newref_t py_script(PyString_FromString(script));
  newref_t py_ret(PyObject_CallFunctionObjArgs(
    py_execscript.o,
    py_script.o,
    GetMainGlobals(),
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
  if ( !interrupted  )
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
  begin_execution();

  char errbuf[MAXSTR];
  bool ok = IDAPython_ExecFile(script, errbuf, sizeof(errbuf));
  if ( !ok )
    warning("IDAPython: error executing '%s':\n%s", script, errbuf);

  end_execution();
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
  const char *defmod = S_IDAAPI_MODNAME)
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
  begin_execution();
  bool ok = IDAPython_ExecFile(filename, errbuf, errbufsize);
  end_execution();
  return ok;
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
  begin_execution();
  bool ok = IDAPython_ExecFile(filename, errbuf, errbufsize, S_IDAAPI_LOADPROCMOD, procobj, true);
  if ( ok && procobj->is_zero() )
  {
    errbuf[0] = '\0';
    ok = false;
  }
  end_execution();
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
  begin_execution();
  bool ok = IDAPython_ExecFile(filename, errbuf, errbufsize, S_IDAAPI_UNLOADPROCMOD);
  end_execution();
  return ok;
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
    begin_execution();
    result = newref_t(PyRun_String(expr, Py_eval_input, globals, globals));
    end_execution();
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

    newref_t py_res(PyObject_CallObject(py_method.o, pargs.empty() ? NULL : pargs[0].o));
    ok = return_python_result(result, py_res, errbuf, errbufsize);
  } while ( false );

  return ok;
}

//-------------------------------------------------------------------------
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
};

//-------------------------------------------------------------------------
void enable_extlang_python(bool enable)
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

  begin_execution();
  PythonEvalOrExec(line);
  end_execution();

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

  bool ok = py_ret != NULL && PyString_Check(py_ret.o) != 0;
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
void enable_python_cli(bool enable)
{
  if ( enable )
      install_command_interpreter(&cli_python);
  else
      remove_command_interpreter(&cli_python);
}

//-------------------------------------------------------------------------
// Prints the IDAPython copyright banner
void py_print_banner()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyRun_SimpleString("print_banner()");
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
    char attr_name[20] = {"0"};
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

#ifdef WITH_HEXRAYS
//-------------------------------------------------------------------------
static bool is_hexrays_plugin(const plugin_info_t *pinfo)
{
  bool is_hx = false;
  if ( pinfo != NULL && pinfo->entry != NULL )
  {
    const plugin_t *p = pinfo->entry;
    if ( streq(p->wanted_name, "Hex-Rays Decompiler") )
      is_hx = true;
  }
  return is_hx;
}
#endif


//------------------------------------------------------------------------
//lint -esym(715,va) Symbol not referenced
static int idaapi on_ui_notification(void *, int code, va_list va)
{
#ifdef WITH_HEXRAYS
  qnotused(va);
#endif
  switch ( code )
  {
    case ui_ready_to_run:
      {
        PYW_GIL_GET; // This hook gets called from the kernel. Ensure we hold the GIL.
        g_ui_ready = true;
        py_print_banner();

        if ( g_run_when == run_on_ui_ready )
          RunScript(g_run_script);
      }
      break;

    case ui_database_inited:
      {
        PYW_GIL_GET; // This hook gets called from the kernel. Ensure we hold the GIL.
        convert_idc_args();
        if ( g_run_when == run_on_db_open )
          RunScript(g_run_script);
      }
      break;

#ifdef WITH_HEXRAYS
    case ui_plugin_loaded:
      if ( hexdsp == NULL )
      {
        if ( is_hexrays_plugin(va_arg(va, plugin_info_t *)) )
        {
          init_hexrays_plugin(0);
          if ( hexdsp != NULL )
            msg("IDAPython Hex-Rays bindings initialized.\n");
        }
      }
      break;

    case ui_plugin_unloading:
      {
        if ( hexdsp != NULL )
        {
          // Hex-Rays will close. Make sure all the refcounted cfunc_t objects
          // are cleared right away.
          if ( is_hexrays_plugin(va_arg(va, plugin_info_t *)) )
          {
            hexrays_clear_python_cfuncptr_t_references();
            hexdsp = NULL;
          }
        }
      }
      break;
#endif

    default:
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
//lint -esym(526,til_clear_python_tinfo_t_instances) not defined
extern void til_clear_python_tinfo_t_instances(void);
static int idaapi on_idp_notification(void *, int code, va_list)
{
  switch ( code )
  {
    case processor_t::closebase:
      // The til machinery is about to garbage-collect: We must go
      // through all the tinfo_t objects that are embedded in SWIG wrappers,
      // (i.e., that were created from Python) and clear those.
      til_clear_python_tinfo_t_instances();
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
// remove current directory (empty entry) from the sys.path
static void sanitize_path()
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
// Initialize the Python environment
bool IDAPython_Init(void)
{
  if ( Py_IsInitialized() != 0 )
    return true;

  // Form the absolute path to IDA\python folder
  qstrncpy(g_idapython_dir, idadir(PYTHON_DIR_NAME), sizeof(g_idapython_dir));

  // Check for the presence of essential files
  if ( !CheckScriptFiles() )
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
  read_user_config_file("python.cfg", set_python_options, NULL);
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
    Py_SetPythonHome(g_idapython_dir);

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
  sanitize_path();

  // import "site"
  if ( !g_use_local_python && !initsite() )
  {
    warning("IDAPython: importing \"site\" failed");
    return false;
  }

  // Enable multi-threading support
  if ( !PyEval_ThreadsInitialized() )
    PyEval_InitThreads();

  // Init the SWIG wrapper
  init_idaapi();

#ifdef Py_DEBUG
  msg("HexraysPython: Python compiled with DEBUG enabled.\n");
#endif

  // Set IDAPYTHON_VERSION in Python
  qsnprintf(
          tmp,
          sizeof(tmp),
          "IDAPYTHON_VERSION=(%d, %d, %d, '%s', %d)\n"
          "IDAPYTHON_REMOVE_CWD_SYS_PATH = %s\n",
          VER_MAJOR,
          VER_MINOR,
          VER_PATCH,
          VER_STATUS,
          VER_SERIAL,
          g_remove_cwd_sys_path ? "True" : "False");
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
