//---------------------------------------------------------------------
// IDAPython - Python plugin for Interactive Disassembler Pro
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

#include <stdio.h>
#include <string.h>
#ifdef __LINUX__
#include <dlfcn.h>
#endif
#ifdef __MAC__
#include <mach-o/dyld.h>
#endif
#include <ida.hpp>
#include <idp.hpp>
#include <ieee.h>
#include <bytes.hpp>
#include <diskio.hpp>
#include <expr.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>
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
static const char S_IDC_ARGS_VARNAME[] =         "ARGV";
static const char S_MAIN[] =                     "__main__";
static const char S_IDC_RUNPYTHON_STATEMENT[] =  "RunPythonStatement";
static const char S_HOTKEY_RUNSTATEMENT[] =      "Alt-8";
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
static bool g_initialized = false;
static bool g_menu_installed = false;
static int  g_run_when = -1;
static char g_run_script[QMAXPATH];
static char g_idapython_dir[QMAXPATH];

//-------------------------------------------------------------------------
// Prototypes and forward declarations

// Alias to SWIG_Init
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
void end_execution();
void begin_execution();

//------------------------------------------------------------------------
// This callback is called on various interpreter events
static int break_check(PyObject *obj, _frame *frame, int what, PyObject *arg)
{
  if ( wasBreak() )
  {
    /* User pressed Cancel in the waitbox; send KeyboardInterrupt exception */
    PyErr_SetInterrupt();
  }
  else if ( !box_displayed && ++ninsns > 10 )
  {
    /* We check the timer once every 10 calls */
    ninsns = 0;
    if ( script_timeout != 0 && (time(NULL) - start_time > script_timeout) ) /* Timeout elapsed? */
    {
      box_displayed = true;
      show_wait_box("Running Python script");
    }
  }
#ifdef ENABLE_PYTHON_PROFILING
  return tracefunc(obj, frame, what, arg);
#else
  return 0;
#endif
}

//------------------------------------------------------------------------
// Prepare for Python execution
void begin_execution()
{
  if ( !g_ui_ready || script_timeout == 0 )
    return;

  ninsns = 0;
  end_execution();
  box_displayed = false;
  start_time = time(NULL);
  PyEval_SetTrace(break_check, NULL);
}

//------------------------------------------------------------------------
// Called after Python execution finishes
void end_execution()
{
  if ( box_displayed )
  {
    hide_wait_box();
    box_displayed = false;
  }

#ifdef ENABLE_PYTHON_PROFILING
  PyEval_SetTrace(tracefunc, NULL);
#else
  PyEval_SetTrace(NULL, NULL);
#endif
}

//-------------------------------------------------------------------------
// Exported to the Python environment
int set_script_timeout(int timeout)
{
  if ( timeout == 0 )
    end_execution();

  qswap(timeout, script_timeout);

  if ( script_timeout != 0 )
    begin_execution();
  return timeout;
}

//-------------------------------------------------------------------------
// Converts IDC arguments to Python argument list or just one tuple
// If 'decref' is NULL then 'pargs' will contain one element which is the tuple
static bool convert_args(
  const idc_value_t args[],
  int nargs,
  ppyobject_vec_t &pargs,
  boolvec_t *decref,
  char *errbuf,
  size_t errbufsize)
{
  bool as_tupple = decref == NULL;
  PyObject *py_tuple(NULL);

  pargs.qclear();

  if ( as_tupple )
  {
    py_tuple = PyTuple_New(nargs);
    if ( py_tuple == NULL )
    {
      qstrncpy(errbuf, "Failed to create a new tuple to store arguments!", errbufsize);
      return false;
    }
    // Add the tuple
    pargs.push_back(py_tuple);
  }
  else
  {
    decref->qclear();
  }

  for ( int i=0; i<nargs; i++ )
  {
    PyObject *py_obj(NULL);
    int cvt = idcvar_to_pyvar(args[i], &py_obj);
    if ( cvt < CIP_OK )
    {
      qsnprintf(errbuf, errbufsize, "arg#%d has wrong type %d", i, args[i].vtype);
      return false;
    }

    if ( as_tupple )
    {
      // Opaque object?
      if ( cvt == CIP_OK_NODECREF )
      {
        // Increment reference for opaque objects.
        // (A tupple will steal references of its set items,
        // and for an opaque object we want it to still exist
        // even if the tuple is gone)
        Py_INCREF(py_obj);
      }
      // Save argument
      PyTuple_SetItem(py_tuple, i, py_obj);
    }
    else
    {
      pargs.push_back(py_obj);
      // do not decrement reference of opaque objects
      decref->push_back(cvt == CIP_OK);
    }
  }
  return true;
}

//-------------------------------------------------------------------------
// Frees arguments returned by convert_args()
static void free_args(
  ppyobject_vec_t &pargs,
  boolvec_t *decref = NULL)
{
  if ( decref == NULL )
  {
    if ( !pargs.empty() )
      Py_XDECREF(pargs[0]);
  }
  else
  {
    // free argument objects
    for ( int i=(int)pargs.size()-1; i>=0; i-- )
    {
      if ( decref->at(i) )
        Py_DECREF(pargs[i]);
    }
    decref->clear();
  }
  pargs.clear();
}

//------------------------------------------------------------------------
// Return a formatted error or just print it to the console
static void handle_python_error(char *errbuf, size_t errbufsize)
{
  if ( errbufsize > 0 )
    errbuf[0] = '\0';

  if ( !PyErr_Occurred() )
    return;

  PyObject *result;
  PyObject *ptype, *pvalue, *ptraceback;
  PyErr_Fetch(&ptype, &pvalue, &ptraceback);
  result = PyObject_Str(pvalue);
  if ( result != NULL )
  {
    qsnprintf(errbuf, errbufsize, "ERROR: %s", PyString_AsString(result));
    PyErr_Clear();
    Py_XDECREF(ptype);
    Py_XDECREF(pvalue);
    Py_XDECREF(ptraceback);
    Py_DECREF(result);
  }
  else
  {
    PyErr_Print();
  }
}

//------------------------------------------------------------------------
// Helper function to get globals for the __main__ module
// Note: The references are borrowed. No need to free them.
PyObject *GetMainGlobals()
{
  PyObject *module = PyImport_AddModule(S_MAIN);
  if ( module == NULL )
      return NULL;
  return PyModule_GetDict(module);
}

//------------------------------------------------------------------------
// Simple Python statement runner function for IDC
static const char idc_runpythonstatement_args[] = { VT_STR2, 0 };
static error_t idaapi idc_runpythonstatement(idc_value_t *argv, idc_value_t *res)
{
  PyObject *globals = GetMainGlobals();
  if ( globals == NULL )
  {
    res->set_string("internal error");
  }
  else
  {
    PyErr_Clear();

    begin_execution();
    PyObject *result = PyRun_String(argv[0].c_str(), Py_file_input, globals, globals );
    Py_XDECREF(result);
    end_execution();

    if ( result == NULL || PyErr_Occurred() )
    {
      char errbuf[MAXSTR];
      handle_python_error(errbuf, sizeof(errbuf));
      if ( errbuf[0] == '\0' )
        res->set_string("internal error");
      else
        res->set_string(errbuf);
    }
    else
    {
      // success
      res->set_long(0);
    }
  }
  return eOk;
}

//-------------------------------------------------------------------------
// Check for the presence of a file in IDADIR/python and complain on error
bool CheckScriptFiles()
{
  static const char *const script_files[] =
  {
    S_IDC_MODNAME ".py",
    "init.py",
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
  PyObject *PyFileObject = PyFile_FromString((char*)FileName, "r");
  PyObject *globals = GetMainGlobals();
  if ( globals == NULL || PyFileObject == NULL )
  {
    Py_XDECREF(PyFileObject);
    return 0;
  }
  PyErr_Clear();
  PyObject *result = PyRun_File(PyFile_AsFile(PyFileObject), FileName, Py_file_input, globals, globals);
  Py_XDECREF(PyFileObject);
  Py_XDECREF(result);
  return result != NULL && !PyErr_Occurred();
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

  if ( asktext(sizeof(statement), statement, statement, "Enter Python expressions") != NULL )
  {
    begin_execution();
    PyRun_SimpleString(statement);
    end_execution();

    // Store the statement to the database
    history.setblob(statement, strlen(statement) + 1, 0, 'A');
  }
}

//-------------------------------------------------------------------------
// This function will call the Python function 'idaapi.IDAPython_ExecFile'
// It does not use 'import', thus the executed script will not yield a new module name
// It returns the exception and traceback information.
// We use the Python function to execute the script because it knows how to deal with
// module reloading.
static bool IDAPython_ExecFile(const char *FileName, char *errbuf, size_t errbufsz)
{
  PyObject *py_execscript = get_idaapi_attr(S_IDAAPI_EXECSCRIPT);
  if ( py_execscript == NULL )
    return false;

  char script[MAXSTR];
  qstrncpy(script, FileName, sizeof(script));
  strrpl(script, '\\', '//');

  PyObject *py_script = PyString_FromString(script);
  PyObject *py_ret = PyObject_CallFunctionObjArgs(py_execscript, py_script, GetMainGlobals(), NULL);
  Py_DECREF(py_script);
  Py_DECREF(py_execscript);

  // Failure at this point means the script was interrupted
  qstring err;
  if ( PyW_GetError(&err) || py_ret == NULL )
  {
    PyErr_Clear();
    if ( err.empty() )
      qstrncpy(errbuf, "Script interrupted", errbufsz);
    else
      qstrncpy(errbuf, err.c_str(), errbufsz);
    Py_XDECREF(py_ret);
    return false;
  }

  bool ok;
  if ( py_ret == Py_None )
    ok = true;
  else if ( PyString_Check(py_ret) )
  {
    qstrncpy(errbuf, PyString_AsString(py_ret), errbufsz);
    ok = false;
  }
  // Cannot be otherwise!
  else
    INTERR();

  Py_XDECREF(py_ret);
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
bool idaapi IDAPython_Menu_Callback(void *ud)
{
  // note: on 64-bit systems the pointer will be truncated to 32-bits!
  run((ssize_t)ud);
  return true;
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
// Convert return value from Python to IDC or report about an error.
// This function also decrements the reference "result" (python variable)
static bool return_python_result(
  idc_value_t *idc_result,
  PyObject *py_result,
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

  if ( cvt != CIP_OK_NODECREF )
    Py_XDECREF(py_result);

  return cvt >= CIP_OK;
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
  PyObject *globals = GetMainGlobals();
  QASSERT(globals != NULL);

  PyCodeObject *code = (PyCodeObject *)Py_CompileString(expr, "<string>", Py_eval_input);
  if ( code == NULL )
  {
    handle_python_error(errbuf, errbufsize);
    return false;
  }

  // set the desired function name
  Py_XDECREF(code->co_name);
  code->co_name = PyString_FromString(name);

  // create a function out of code
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

  return true;
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
  // Try to extract module name (if any) from the funcname
  char modname[MAXSTR] = {0};
  char funcname[MAXSTR] = {0};
  bool imported_module = parse_py_modname(name, modname, funcname, MAXSTR);

  ppyobject_vec_t pargs;
  boolvec_t decref;
  bool ok = true;
  PyObject *module = NULL;
  do
  {
    // Convert arguments to python
    ok = convert_args(args, nargs, pargs, &decref, errbuf, errbufsize);
    if ( !ok )
      break;

    if ( imported_module )
    {
      module = PyImport_ImportModule(modname);
    }
    else
    {
      module = PyImport_AddModule(S_MAIN);
      QASSERT(module != NULL);
    }

    PyObject *globals = PyModule_GetDict(module);
    QASSERT(globals != NULL);

    PyObject *func = PyDict_GetItemString(globals, funcname);
    if ( func == NULL )
    {
      qsnprintf(errbuf, errbufsize, "undefined function %s", name);
      ok = false;
      break;
    }
    PyCodeObject *code = (PyCodeObject *) PyFunction_GetCode(func);
    PyObject *pres = PyEval_EvalCodeEx(
                        code,
                        globals, NULL, &pargs[0], nargs,
                        NULL, 0, NULL, 0, NULL);
    ok = return_python_result(result, pres, errbuf, errbufsize);
  } while ( false );

  free_args(pargs, &decref);

  if ( imported_module )
    Py_XDECREF(module);
  return ok;
}

//-------------------------------------------------------------------------
// Compile callback for Python external language evaluator
bool idaapi IDAPython_extlang_compile_file(
  const char *filename,
  char *errbuf,
  size_t errbufsize)
{
  begin_execution();
  bool ok = IDAPython_ExecFile(filename, errbuf, errbufsize);
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
  PyObject *py_mod(NULL), *py_cls(NULL);
  ppyobject_vec_t pargs;

  bool ok = false;
  do
  {
    // Parse the object name (to get the module and class name)
    char modname[MAXSTR] = {0};
    char clsname[MAXSTR] = {0};
    parse_py_modname(name, modname, clsname, MAXSTR);

    // Get a reference to the module
    py_mod = PyW_TryImportModule(modname);
    if ( py_mod == NULL )
    {
      qsnprintf(errbuf, errbufsize, "Could not import module '%s'!", modname);
      break;
    }

    // Get the class reference
    py_cls = PyW_TryGetAttrString(py_mod, clsname);
    if ( py_cls == NULL )
    {
      qsnprintf(errbuf, errbufsize, "Could not find class type '%s'!", clsname);
      break;
    }

    // Error during conversion?
    ok = convert_args(args, nargs, pargs, NULL, errbuf, errbufsize);
    if ( !ok )
      break;
    ok = false;

    // Call the constructor
    PyObject *py_res = PyObject_CallObject(py_cls, pargs.empty() ? NULL : pargs[0]);
    ok = return_python_result(result, py_res, errbuf, errbufsize);
  } while ( false );

  Py_XDECREF(py_mod);
  Py_XDECREF(py_cls);

  // Free the arguments tuple
  free_args(pargs);
  return ok;
}

//-------------------------------------------------------------------------
// Returns the attribute value of a given object from the global scope
bool idaapi IDAPython_extlang_get_attr(
  const idc_value_t *obj, // in: object (may be NULL)
  const char *attr,       // in: attribute name
  idc_value_t *result)
{
  PyObject *py_mod(NULL), *py_obj(NULL);
  bool is_opaque_obj = false;
  int cvt = CIP_FAILED;
  do
  {
    // Get a reference to the module
    py_mod = PyW_TryImportModule(S_MAIN);
    if ( py_mod == NULL )
      break;

    // Object specified:
    // - (1) string contain attribute name in the main module
    // - (2) opaque object (we use it as is)
    if ( obj != NULL )
    {
      // (1) Get attribute from main module
      if ( obj->vtype == VT_STR2 )
        py_obj = PyW_TryGetAttrString(py_mod, obj->c_str());
      // (2) see if opaque object
      else
      {
        // Convert object (expecting opaque object)
        cvt = idcvar_to_pyvar(*obj, &py_obj);
        // Only opaque objects are accepted
        if ( cvt != CIP_OK_NODECREF )
        {
          Py_XDECREF(py_obj);
          py_obj = NULL;
          cvt = CIP_FAILED;
          break;
        }
        is_opaque_obj = true;
      }
      // Get the attribute reference
      if ( py_obj == NULL )
        break;
    }
    // No object specified:
    else
    {
      // then work with main module
      py_obj = py_mod;
    }
    PyObject *py_attr = PyW_TryGetAttrString(py_obj, attr);
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
      Py_DECREF(py_attr);
    }
    else
    {
      cvt = pyvar_to_idcvar(py_attr, result);
      // Conversion succeeded and opaque object was passed:
      // Since the object will be passed to IDC, it is likely that IDC value will be
      // destroyed and also destroying the opaque object with it. That is an undesired effect.
      // We increment the reference of the object so that even if the IDC value dies
      // the opaque object remains. So by not decrement reference after GetAttrString() call
      // we are indirectly increasing the reference. If it was not opaque then we decrement the reference.
      if ( cvt >= CIP_OK && cvt != CIP_OK_NODECREF )
      {
        // Decrement the reference (that was incremented by GetAttrString())
        Py_DECREF(py_attr);
      }
    }
  } while ( false );

  // Free main module reference
  Py_XDECREF(py_mod);

  // Wasn't working with main module?
  if ( obj != NULL && !is_opaque_obj )
      Py_XDECREF(py_obj);

  return cvt >= CIP_OK;
}

//-------------------------------------------------------------------------
// Returns the attribute value of a given object from the global scope
bool idaapi IDAPython_extlang_set_attr(
  idc_value_t *obj,       // in: object name (may be NULL)
  const char *attr,       // in: attribute name
  idc_value_t *value)
{
  PyObject *py_mod(NULL), *py_obj(NULL);
  bool ok = false, is_opaque_obj = false;
  do
  {
    // Get a reference to the module
    py_mod = PyW_TryImportModule(S_MAIN);
    if ( py_mod == NULL )
      break;

    if ( obj != NULL )
    {
      // Get the attribute reference (from just a name)
      if ( obj->vtype == VT_STR2 )
        py_obj = PyW_TryGetAttrString(py_mod, obj->c_str());
      else
      {
        int cvt = idcvar_to_pyvar(*obj, &py_obj);
        // Only opaque objects are accepted
        if ( cvt != CIP_OK_NODECREF )
        {
          Py_XDECREF(py_obj);
          py_obj = NULL;
        }
        else
          is_opaque_obj = true;
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
    PyObject *py_var(NULL);
    int cvt = idcvar_to_pyvar(*value, &py_var);
    if ( cvt >= CIP_OK )
    {
      ok = PyObject_SetAttrString(py_obj, attr, py_var) != -1;
      if ( cvt != CIP_OK_NODECREF )
        Py_XDECREF(py_var);
    }
  } while ( false );

  Py_XDECREF(py_mod);

  if ( obj != NULL && !is_opaque_obj )
    Py_XDECREF(py_obj);

  return ok;
}

//-------------------------------------------------------------------------
// Calculator callback for Python external language evaluator
bool idaapi IDAPython_extlang_calcexpr(
  ea_t /*current_ea*/,
  const char *expr,
  idc_value_t *rv,
  char *errbuf,
  size_t errbufsize)
{
  PyObject *globals = GetMainGlobals();
  if ( globals == NULL )
    return false;

  begin_execution();
  PyObject *result = PyRun_String(expr, Py_eval_input, globals, globals);
  end_execution();

  return return_python_result(rv, result, errbuf, errbufsize);
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
  // Check for unsupported usage of call_method.
  // Mainly a method call requires an object and a method.
  if ( (idc_obj == NULL && method_name == NULL) || (idc_obj != NULL && method_name == NULL) )
  {
    qstrncpy(errbuf, "call_method does not support this operation", errbufsize);
    return false;
  }
  // Behave like run()
  else if ( idc_obj == NULL && method_name != NULL )
      return IDAPython_extlang_run(method_name, nargs, args, result, errbuf, errbufsize);

  PyObject *py_obj(NULL), *py_method(NULL);
  // Holds conversion status of input object
  int obj_cvt;
  ppyobject_vec_t pargs;
  bool ok = false;
  do
  {
    // Convert input object
    obj_cvt = idcvar_to_pyvar(*idc_obj, &py_obj);
    if ( obj_cvt < CIP_OK )
    {
      qstrncpy(errbuf, "Failed to convert input object to Python value", errbufsize);
      break;
    }

    py_method = PyW_TryGetAttrString(py_obj, method_name);
    if ( py_method == NULL || !PyCallable_Check(py_method) )
    {
      qsnprintf(errbuf, errbufsize, "The input object does not have a callable method called '%s'", method_name);
      break;
    }

    // Convert arguments to python objects
    ok = convert_args(args, nargs, pargs, NULL, errbuf, errbufsize);
    if ( !ok )
      break;

    PyObject *py_res = PyObject_CallObject(py_method, pargs.empty() ? NULL : pargs[0]);
    ok = return_python_result(result, py_res, errbuf, errbufsize);
  } while ( false );

  // Free converted args
  free_args(pargs);

  // Release reference of object if needed
  if ( obj_cvt != CIP_OK_NODECREF )
    Py_XDECREF(py_obj);

  Py_XDECREF(py_method);
  return ok;
}

//-------------------------------------------------------------------------
extlang_t extlang_python =
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
    IDAPython_extlang_call_method
};

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
  const char *first_line = strrchr(line, '\n');
  if ( first_line == NULL )
    first_line = line;
  else
    first_line += 1;

  // skip empty lines
  if ( first_line[0] != '\0' )
  {
    // take a copy of the line so we r-trim it
    char *tline = qstrdup(first_line);
    trim(tline);

    // line ends with ":" or begins with a space character?
    bool more = tline[qstrlen(tline)-1] == ':' || isspace(first_line[0]);
    qfree(tline);

    if ( more )
      return false;
  }

  begin_execution();
  PyRun_SimpleString(line);
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
  PyObject *py_complete = get_idaapi_attr(S_IDAAPI_COMPLETION);
  if ( py_complete == NULL )
    return false;

  PyObject *py_ret = PyObject_CallFunction(py_complete, "sisi", prefix, n, line, x);

  Py_DECREF(py_complete);

  // Swallow the error
  PyW_GetError(completion);

  bool ok = py_ret != NULL && PyString_Check(py_ret) != 0;

  if ( ok )
    *completion = PyString_AS_STRING(py_ret);

  Py_XDECREF(py_ret);

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
  PyRun_SimpleString("print_banner()");
}

//-------------------------------------------------------------------------
// Install python menu items
static void install_python_menus()
{
  if ( g_menu_installed )
    return;

  // Add menu items for all the functions
  // Note: Different paths are used for the GUI version
  add_menu_item("File/IDC command...", "P~y~thon command...",
    S_HOTKEY_RUNSTATEMENT, SETMENU_APP,
    IDAPython_Menu_Callback,
    (void *)IDAPYTHON_RUNSTATEMENT);

  g_menu_installed = true;
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
  PyObject *py_args = PyList_New(0);

  idc_value_t *idc_args = find_idc_gvar(S_IDC_ARGS_VARNAME);
  if ( idc_args != NULL )
  {
    idc_value_t attr;
    char attr_name[20] = {"0"};
    for ( int i=1; VarGetAttr(idc_args, attr_name, &attr) == eOk; i++ )
    {
      PyList_Insert(py_args, i, PyString_FromString(attr.c_str()));
      qsnprintf(attr_name, sizeof(attr_name), "%d", i);
    }
  }

  // Get reference to the IDC module (it is imported by init.py)
  PyObject *py_mod = PyW_TryImportModule(S_IDC_MODNAME);
  if ( py_mod != NULL )
    PyObject_SetAttrString(py_mod, S_IDC_ARGS_VARNAME, py_args);

  Py_DECREF(py_args);
  Py_XDECREF(py_mod);
}

//------------------------------------------------------------------------
// We install the menu later because the text version crashes if
// add_menu_item is called too early
static int idaapi menu_installer_cb(void *, int code, va_list)
{
  switch ( code )
  {
    case ui_ready_to_run:
      g_ui_ready = true;
      py_print_banner();
      install_python_menus();

      if ( g_run_when == run_on_ui_ready )
          RunScript(g_run_script);
      break;

    case ui_database_inited:
      {
        convert_idc_args();
        if ( g_run_when == run_on_db_open )
          RunScript(g_run_script);
        break;
      }
    default:
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
// Initialize the Python environment
bool IDAPython_Init(void)
{
  // Already initialized?
  if ( g_initialized  )
    return true;

  // Form the absolute path to IDA\python folder
  qstrncpy(g_idapython_dir, idadir(PYTHON_DIR_NAME), sizeof(g_idapython_dir));

  // Check for the presence of essential files
  if ( !CheckScriptFiles() )
    return false;

  char tmp[MAXSTR+64];
#ifdef __LINUX__
  // Export symbols from libpython to resolve imported module deps
  qsnprintf(tmp, sizeof(tmp), "libpython%d.%d.so",
    PY_MAJOR_VERSION,
    PY_MINOR_VERSION);
  if ( !dlopen(tmp, RTLD_NOLOAD | RTLD_GLOBAL | RTLD_LAZY) )
  {
    warning("IDAPython: %s", dlerror());
    return false;
  }
#endif

#ifdef __MAC__
  // We should set python home to the module's path, otherwise it can pick up stray modules from $PATH
  NSModule pythonModule = NSModuleForSymbol(NSLookupAndBindSymbol("_Py_Initialize"));
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

  // Start the interpreter
  Py_Initialize();
  if ( !Py_IsInitialized() )
  {
    warning("IDAPython: Py_Initialize() failed");
    return false;
  }

  // Init the SWIG wrapper
  init_idaapi();

  // Set IDAPYTHON_VERSION in Python
  qsnprintf(tmp, sizeof(tmp), "IDAPYTHON_VERSION=(%d, %d, %d, '%s', %d)", \
    VER_MAJOR,
    VER_MINOR,
    VER_PATCH,
    VER_STATUS,
    VER_SERIAL);
  PyRun_SimpleString(tmp);

  // Execute init.py (for Python side initialization)
  qmakepath(tmp, MAXSTR, g_idapython_dir, "init.py", NULL);
  if ( !PyRunFile(tmp) )
  {
    handle_python_error(tmp, sizeof(tmp));
    warning("IDAPython: error executing init.py:\n%s", tmp);
    return false;
  }

  // Init pywraps and notify_when
  if ( !init_pywraps() || !pywraps_nw_init() )
  {
    warning("IDAPython: init_pywraps() failed!");
    return false;
  }

#ifdef ENABLE_PYTHON_PROFILING
  PyEval_SetTrace(tracefunc, NULL);
#endif

  // Batch-mode operation:
  parse_plugin_options();

  // Register a RunPythonStatement() function for IDC
  set_idc_func(S_IDC_RUNPYTHON_STATEMENT, idc_runpythonstatement, idc_runpythonstatement_args);

  // A script specified on the command line is run
  if ( g_run_when == run_on_init )
    RunScript(g_run_script);

#ifdef PLUGINFIX
  hook_to_notification_point(HT_UI, menu_installer_cb, NULL);
#else
  install_python_menus();
  py_print_banner();
#endif

  // Enable the CLI by default
  enable_python_cli(true);

  // Install extlang
  install_extlang(&extlang_python);

  g_initialized = true;
  pywraps_nw_notify(NW_INITIDA_SLOT);
  return true;
}

//-------------------------------------------------------------------------
// Cleaning up Python
void IDAPython_Term(void)
{
#ifdef PLUGINFIX
  unhook_from_notification_point(HT_UI, menu_installer_cb, NULL);
#endif
  /* Remove the menu items before termination */
  del_menu_item("File/Python command...");
  g_menu_installed = false;

  // Remove the CLI
  enable_python_cli(false);

  // Remove the extlang
  remove_extlang(&extlang_python);

  // Notify about IDA closing
  pywraps_nw_notify(NW_TERMIDA_SLOT);

  // De-init notify_when
  pywraps_nw_term();

  // De-init pywraps
  deinit_pywraps();

  // Uninstall IDC function
  set_idc_func(S_IDC_RUNPYTHON_STATEMENT, NULL, NULL);

  // Shut the interpreter down
  Py_Finalize();

  g_initialized = false;
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
#ifdef PLUGINFIX
  PLUGIN_FIX,    // plugin flags
#else
  0,             // plugin flags
#endif
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
  S_HOTKEY_RUNSTATEMENT
};
