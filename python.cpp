//------------------------------------------------------------
// IDAPython - Python plugin for Interactive Disassembler Pro
//
// Copyright (c) 2004-2009 Gergely Erdelyi <dyce@d-dome.net>
//
// All rights reserved.
//
// For detailed copyright information see the file COPYING in
// the root of the distribution archive.
//------------------------------------------------------------
// python.cpp - Main plugin code
//------------------------------------------------------------
#include <Python.h>

/* This define fixes the redefinition of ssize_t */
#ifdef HAVE_SSIZE_T
#define _SSIZE_T_DEFINED 1
#endif

#include <stdio.h>
#include <string.h>
#ifdef __LINUX__
#include <dlfcn.h>
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

#ifdef __cplusplus
extern "C"
#endif

/* Python-style version tuple comes from the makefile */
/* Only the serial and status is set here */
#define VER_SERIAL 0
#define VER_STATUS "final"

#define IDAPYTHON_RUNFILE      0
#define IDAPYTHON_RUNSTATEMENT 1
#define IDAPYTHON_SCRIPTBOX    2


#define IDAPYTHON_DATA_STATEMENT 0

#define PYTHON_DIR_NAME "python"

void init_idaapi(void);
void idaapi run(int arg);
static int initialized = 0;
static bool menu_installed = false;
//--------------------------------------------------------------------------
// Some utility functions from pywraps / idaapi
int idcvar_to_pyvar(const idc_value_t &idc_var, PyObject **py_var);
int pyvar_to_idcvar(PyObject *py_var, idc_value_t *idc_var, int *gvar_sn = NULL);
PyObject *PyObject_TryGetAttrString(PyObject *py_var, const char *attr);
PyObject *PyImport_TryImportModule(const char *name);
bool PyGetError(qstring *out = NULL);
bool init_pywraps();
void deinit_pywraps();
static const char S_MAIN[] = "__main__";
//--------------------------------------------------------------------------

/* This is a simple tracing code for debugging purposes. */
/* It might evolve into a tracing facility for user scripts. */
/* #define ENABLE_PYTHON_PROFILING */

#ifdef ENABLE_PYTHON_PROFILING
#include "compile.h"
#include "frameobject.h"

int tracefunc(PyObject *obj, _frame *frame, int what, PyObject *arg)
{
    PyObject *str;

    /* Catch line change events. */
    /* Print the filename and line number */
    if (what == PyTrace_LINE)
    {
        str = PyObject_Str(frame->f_code->co_filename);
        if (str)
        {
            msg("PROFILING: %s:%d\n", PyString_AsString(str), frame->f_lineno);
            Py_DECREF(str);
        }
    }
    return 0;
}
#endif

/* Helper routines to make Python script execution breakable from IDA */
static int ninsns = 0;      // number of times trace function was called
static bool box_displayed;  // has the wait box been displayed?
static time_t start_time;   // the start time of the execution
static int script_timeout = 2;

/* Exported to the Python environment */
void set_script_timeout(int timeout)
{
    script_timeout = timeout;
}

/* This callback is called on various interpreter events */
int break_check(PyObject *obj, _frame *frame, int what, PyObject *arg)
{
    if (wasBreak())
        /* User pressed Cancel in the waitbox; send KeyboardInterrupt exception */
        PyErr_SetInterrupt();
    else if (!box_displayed && ++ninsns > 10)
    {
        /* We check the timer once every 10 calls */
        ninsns = 0;
        if (time(NULL) - start_time > script_timeout) /* Timeout elapsed? */
        {
            show_wait_box("Running Python script");
            box_displayed = true;
        }
    }
#ifdef ENABLE_PYTHON_PROFILING
    return tracefunc(obj, frame, what, arg);
#else
    return 0;
#endif
}

/* Prepare for Python execution */
void begin_execution()
{
    ninsns = 0;
    box_displayed = false;
    start_time = time(NULL);
    PyEval_SetTrace(break_check, NULL);
}

/* Called after Python execution finishes */
void end_execution()
{
    if (box_displayed)
        hide_wait_box();
#ifdef ENABLE_PYTHON_PROFILING
    PyEval_SetTrace(tracefunc, NULL);
#else
    PyEval_SetTrace(NULL, NULL);
#endif
}

/* Return a formatted error or just print it to the console */
static void handle_python_error(char *errbuf, size_t errbufsize)
{
  PyObject *result;
  PyObject *ptype, *pvalue, *ptraceback;

  if ( errbufsize > 0 )
    errbuf[0] = '\0';

  if (PyErr_Occurred())
  {
    PyErr_Fetch(&ptype, &pvalue, &ptraceback);
    result = PyObject_Repr(pvalue);
    if (result)
    {
      qsnprintf(errbuf, errbufsize, "ERROR: %s", PyString_AsString(result));
      PyErr_Clear();
      Py_XDECREF(ptype);
      Py_XDECREF(pvalue);
      Py_XDECREF(ptraceback);
    }
    else
      PyErr_Print();
  }
}

/* helper function to get globals for the __main__ module */
PyObject *GetMainGlobals()
{
    PyObject *module = PyImport_AddModule(S_MAIN);
    if (module == NULL)
        return NULL;

    return PyModule_GetDict(module);
}

/* Simple Python statement runner function for IDC */
static const char idc_runpythonstatement_args[] = { VT_STR2, 0 };
static error_t idaapi idc_runpythonstatement(idc_value_t *argv, idc_value_t *res)
{
    PyObject *globals = GetMainGlobals();
    if (globals == NULL)
    {
      res->set_string("internal error");
    }
    else
    {
      PyErr_Clear();
      begin_execution();
      PyObject *result = PyRun_String(argv[0].c_str(), Py_file_input, globals, globals );
      end_execution();
      Py_XDECREF(result);
      if ( result == NULL || PyErr_Occurred() )
      {
        char errbuf[MAXSTR];
        handle_python_error(errbuf, sizeof(errbuf));
        *res = idc_value_t(errbuf);
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

/* QuickFix for the FILE* incompatibility problem */
int ExecFile(const char *FileName)
{
    PyObject *PyFileObject = PyFile_FromString((char*)FileName, "r");

    PyObject *globals = GetMainGlobals();
    if (globals == NULL)
        return 0;

    PyErr_Clear();
    PyObject *result = PyRun_File(PyFile_AsFile(PyFileObject), FileName, Py_file_input, globals, globals);

    Py_XDECREF(PyFileObject);
    Py_XDECREF(result);
    if ( result == NULL || PyErr_Occurred() )
    {
      if ( !PyErr_Occurred() )
        PyErr_Print();
      return 0;
    }

    return 1;
}

/* Check for the presence of a file in IDADIR/python */
bool CheckFile(char *filename)
{
    char filepath[MAXSTR+1];

    qmakepath(filepath, MAXSTR, idadir(PYTHON_DIR_NAME), filename, NULL);
    if (!qfileexist(filepath))
    {
        warning("IDAPython: Missing required file %s", filename);
        return false;
    }

    return true;
}

/* Execute the Python script from the plugin */
/* Default hotkey: Alt-9 */
void IDAPython_RunScript(const char *script)
{
    char statement[MAXSTR+32];
    char slashpath[MAXSTR+1];
    const char *scriptpath;

    int i;

    if (script)
        scriptpath = script;
    else
    {
        scriptpath = askfile_c(0, "*.py", "Python file to run");
        if (!scriptpath)
            return;
    }

    /* Make a copy of the path with '\\' => '/' */
    for (i=0; scriptpath[i]; i++)
    {
        if (scriptpath[i] == '\\')
            slashpath[i] = '/';
        else
            slashpath[i] = scriptpath[i];
    }
    slashpath[i] = '\0';

    /* Add the script't path to sys.path */
    qsnprintf(statement, sizeof(statement), "runscript(\"%s\")", slashpath);
    begin_execution();
    PyRun_SimpleString(statement);
    end_execution();

    /* Error handling */
    if (PyErr_Occurred())
        PyErr_Print();

}

/* Execute Python statement(s) from an editor window */
/* Default hotkey: Alt-8 */
void IDAPython_RunStatement(void)
{
    char statement[4096];
    netnode history;

    /* Get the existing or create a new netnode in the database */
    history.create("IDAPython_Data");

    /* Fetch the previous statement */
    if (history.supval(IDAPYTHON_DATA_STATEMENT, statement, sizeof(statement)) == -1)
        statement[0] = '\0';

    if (asktext(sizeof(statement), statement, statement, "Enter Python expressions"))
    {
        begin_execution();
        PyRun_SimpleString(statement);
        end_execution();
        /* Store the statement to the database */
        history.supset(IDAPYTHON_DATA_STATEMENT, statement);
    }
}

/* History of previously executed scripts */
/* Default hotkey: Alt-7 */
void IDAPython_ScriptBox(void)
{
    PyObject *dict;
    PyObject *scriptbox;
    PyObject *pystr;

    /* Get globals() */
    /* This should never fail */
    dict = GetMainGlobals();

    scriptbox = PyDict_GetItemString(dict, "scriptbox");

    if (!scriptbox)
    {
        warning("INTERNAL ERROR: ScriptBox_instance missing! Broken init.py?");
        return;
    }

    pystr = PyObject_CallMethod(scriptbox, "run", "");

    if (!pystr)
    {
        /* Print the exception info */
        if (PyErr_Occurred())
            PyErr_Print();
    }
}

bool idaapi IDAPython_Menu_Callback(void *ud)
{
    run((size_t)ud);
    return true;
}


//--------------------------------------------------------------------------
// This function parses a name into two different components (if it applies).
// Example:
// parse_py_modname("modname.attrname", mod_buf, attr_buf)
// It splits the full name into two parts.
static bool parse_py_modname(
  const char *full_name,
  char *modname,
  char *attrname, 
  size_t sz,
  const char *defmod = "idaapi")
{
  const char *p = strchr(full_name, '.');
  if (p == NULL)
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

/* Convert return value from Python to IDC or report about an error. */
/* This function also decrements the reference "result" (python variable) */
static bool return_python_result(idc_value_t *rv,
                                 PyObject *result,
                                 char *errbuf,
                                 size_t errbufsize)
{
    if (errbufsize > 0)
        errbuf[0] = '\0';

    if (result == NULL)
    {
        handle_python_error(errbuf, errbufsize);
        return false;
    }
    bool ok = true;
    if (pyvar_to_idcvar(result, rv) <= 0)
    {
        qsnprintf(errbuf, errbufsize, "ERROR: bad return value");
        ok = false;
    }
    Py_XDECREF(result);
    return ok;
}

/* Compile callback for Python external language evaluator */
bool idaapi IDAPython_extlang_compile(const char *name,
              ea_t /*current_ea*/,
              const char *expr,
              char *errbuf,
              size_t errbufsize)
{
    PyObject *globals = GetMainGlobals();       QASSERT(globals != NULL);

    PyCodeObject *code = (PyCodeObject *)Py_CompileString(expr, "<string>", Py_eval_input);
    if (code == NULL)
    {
        handle_python_error(errbuf, errbufsize);
        return false;
    }

    // set the desired function name
    Py_XDECREF(code->co_name);
    code->co_name = PyString_FromString(name);

    // create a function out of code
    PyObject *func = PyFunction_New((PyObject *)code, globals);
    if (func == NULL)
    {
    ERR:
        handle_python_error(errbuf, errbufsize);
        Py_XDECREF(code);
        return false;
    }

    int err = PyDict_SetItemString(globals, name, func);
    if (err)
        goto ERR;

    return true;
}

/* Run callback for Python external language evaluator */
bool idaapi IDAPython_extlang_run(const char *name,
          int nargs,
          const idc_value_t args[],
          idc_value_t *result,
          char *errbuf,
          size_t errbufsize)
{
    // convert arguments to python
    qvector<PyObject *> pargs;
    qvector<bool> do_decref;

    bool ok = true;

    PyObject *module(NULL);
    char modname[MAXSTR] = {0};
    char funcname[MAXSTR] = {0};
    bool imported_module = parse_py_modname(name, modname, funcname, MAXSTR);
    do
    {
        for (int i=0; i<nargs; i++)
        {
            PyObject *py_obj(NULL);
            int cvt = idcvar_to_pyvar(args[i], &py_obj);
            if (cvt <= 0)
            {
              qsnprintf(errbuf, errbufsize, "arg#%d has wrong type %d", i, args[i].vtype);
              ok = false;
              break;
            }
            pargs.push_back(py_obj);
			// do not decrement reference of opaque objects
            do_decref.push_back(cvt == 1);
        }
        if (!ok)
          break;

        if (imported_module)
        {
          module = PyImport_ImportModule(modname);
        }
        else
        {
          module = PyImport_AddModule(S_MAIN);  QASSERT(module != NULL);
        }
        PyObject *globals = PyModule_GetDict(module); QASSERT(globals != NULL);
        PyObject *func    = PyDict_GetItemString(globals, funcname);

        if (func == NULL)
        {
            qsnprintf(errbuf, errbufsize, "undefined function %s", name);
            ok = false;
            break;
        }

        PyCodeObject *code = (PyCodeObject *)PyFunction_GetCode(func);
        PyObject *pres = PyEval_EvalCodeEx(code, globals, NULL, &pargs[0], nargs,
                                           NULL, 0, NULL, 0, NULL);

        ok = return_python_result(result, pres, errbuf, errbufsize);
    } while (false);

    // free argument objects
    for (int i=0; i<nargs; i++)
    {
      if (do_decref[i])
        Py_DECREF(pargs[i]);
    }

    if (imported_module)
      Py_XDECREF(module);
    return ok;
}

/* Compile callback for Python external language evaluator */
bool idaapi IDAPython_extlang_compile_file(const char *script_path,
                   char *errbuf,
                   size_t errbufsize)
{
    PyObject *globals = GetMainGlobals();       QASSERT(globals != NULL);

    if (!ExecFile(script_path))
    {
        handle_python_error(errbuf, errbufsize);
        return false;
    }

    char modname[MAXSTR] = {0};
    // take the filename.ext part
    qstrncpy(modname, qbasename(script_path), sizeof(modname));
    // take the filename part only
    qsplitfile(modname, NULL, NULL);

    // import the module using its absolute path
    qstring s;
    s.sprnt(
      "import imp\n"
      "imp.load_source('%s', r'%s')", modname, script_path);
    PyRun_SimpleString(s.c_str());

    return true;
}

/* Create an object instance */
bool idaapi IDAPython_extlang_create_object(
  const char *name,       // in: object class name
  int nargs,              // in: number of input arguments
  const idc_value_t args[], // in: input arguments
  idc_value_t *result,    // out: created object or exception
  char *errbuf,           // out: error message if evaluation fails
  size_t errbufsize)     // in: size of the error buffer
{
  PyObject *py_mod(NULL), *py_cls(NULL), *py_args(NULL);
  bool ok = false;
  do
  {
    // Parse the object name (to get the module and class name)
    char modname[MAXSTR] = {0};
    char clsname[MAXSTR] = {0};
    parse_py_modname(name, modname, clsname, MAXSTR);

    // Get a reference to the module
    py_mod = PyImport_TryImportModule(modname);
    if (py_mod == NULL)
    {
      qsnprintf(errbuf, errbufsize, "Could not import module %s!", modname);
      break;
    }
    // Get the class reference
    py_cls = PyObject_TryGetAttrString(py_mod, clsname);
    if (py_cls == NULL)
    {
      qsnprintf(errbuf, errbufsize, "Could not find class %s!", clsname);
      break;
    }

    // Create a tupple
    py_args = PyTuple_New(nargs);
    if (py_args == NULL)
      break;

    // Store all the converted arguments in the tupple
    ok = true;
    for (int i=0;i<nargs;i++)
    {
      PyObject *arg(NULL);
      // Convert the argument
      int cvt = idcvar_to_pyvar(args[i], &arg);
      if (cvt <= 0)
      {
        qsnprintf(errbuf, errbufsize, "Failed while converting argument #%d", i);
        ok = false;
        break;
      }
      // Opaque object?
      if (cvt == 2)
      {
        // Increment reference for opaque objects.
        // A tupple will steal references of its set items,
        // and for an opaque object we want it to still exist
        // even if the tuple is gone.
        Py_INCREF(arg);
      }
      // Save it
      // Steals the reference and that means we are no longer responsible
      // for reference management of the items.
      PyTuple_SetItem(py_args, i, arg);
    }

    // Error during conversion?
    if (!ok)
      break;
    ok = false;

    // Call the constructor
    PyObject *py_res = PyObject_Call(py_cls, py_args, NULL);

    // Call failed?
    if (py_res == NULL)
    {
      // Try to get a meaningful error string
      qstring s;
      if (!PyGetError(&s))
      {
        qsnprintf(errbuf, errbufsize, "Calling the constructor failed!");
      }
      else
      {
        qstrncpy(errbuf, s.c_str(), errbufsize);
      }
      break;
    }
    int r = pyvar_to_idcvar(py_res, result);
    ok = r > 0;
    // decrement reference only if not an opaque object
    if (r == 1)
      Py_DECREF(py_res);
  } while (false);

  Py_XDECREF(py_mod);
  Py_XDECREF(py_cls);

  // Free the arguments tuple
  if (py_args != NULL)
    Py_DECREF(py_args);

  return ok;
}

// Returns: success

/* Calculator callback for Python external language evaluator */
bool idaapi IDAPython_extlang_calcexpr(ea_t /*current_ea*/,
                                       const char *expr,
                                       idc_value_t *rv,
                                       char *errbuf,
                                       size_t errbufsize)
{
    PyObject *result;

    PyObject *globals = GetMainGlobals();
    if (globals == NULL)
        return false;

  begin_execution();
    result = PyRun_String(expr, Py_eval_input, globals, globals);
  end_execution();

    rv->clear();

    return return_python_result(rv, result, errbuf, errbufsize);
}

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
    IDAPython_extlang_create_object
};

void enable_extlang_python(bool enable)
{
#if IDA_SDK_VERSION < 560
#define SELECT_EXTLANG register_extlang
#else
#define SELECT_EXTLANG select_extlang
#endif
    if (enable)
        SELECT_EXTLANG(&extlang_python);
    else
        SELECT_EXTLANG(NULL);
#undef SELECT_EXTLANG
}

#if IDA_SDK_VERSION >= 540
/* Execute a line in the Python CLI */
bool idaapi IDAPython_cli_execute_line(const char *line)
{
  const char *first_line = strrchr(line, '\n');
  if (first_line == NULL)
    first_line = line;
  else
    first_line += 1;

  // skip empty lines
  if (first_line[0] != '\0')
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

cli_t cli_python =
{
    sizeof(cli_t),
    0,
    "Python",
    "Python - IDAPython plugin",
    "Enter any Python expression",
    IDAPython_cli_execute_line,
    NULL,
    NULL
};

/* Control the Python CLI status */
void enable_python_cli(bool enable)
{
    if (enable)
        install_command_interpreter(&cli_python);
    else
        remove_command_interpreter(&cli_python);
}
#endif

/* Prints the IDAPython copyright banner */
void print_banner()
{
  PyRun_SimpleString("print_banner()");
}

/* Install python menu items */
static void install_python_menus()
{
  if (menu_installed)
    return;

  /* Add menu items for all the functions */
  /* Different paths are used for the GUI version */
  add_menu_item("File/IDC command...", "P~y~thon command...",
    "Alt-8", SETMENU_APP,
    (menu_item_callback_t *)IDAPython_Menu_Callback,
    (void *)IDAPYTHON_RUNSTATEMENT);

  /* Add Load Python file menu item*/
  bool result = add_menu_item("File/Load file/IDC file...", "P~y~thon file...",
    "Alt-9", SETMENU_APP,
    (menu_item_callback_t *)IDAPython_Menu_Callback,
    (void *)IDAPYTHON_RUNFILE);
  if (!result)
    add_menu_item("File/IDC command...", "P~y~thon file...",
    "Alt-9", SETMENU_APP,
    (menu_item_callback_t *)IDAPython_Menu_Callback,
    (void *)IDAPYTHON_RUNFILE);

  /* Add View Python Scripts menu item*/
  result = add_menu_item("View/Open subviews/Show strings", "Python S~c~ripts",
    "Alt-7", SETMENU_APP,
    (menu_item_callback_t *)IDAPython_Menu_Callback,
    (void *)IDAPYTHON_SCRIPTBOX);
  if (!result)
    add_menu_item("View/Open subviews/Problems", "Python S~c~ripts",
    "Alt-7", SETMENU_APP,
    (menu_item_callback_t *)IDAPython_Menu_Callback,
    (void *)IDAPYTHON_SCRIPTBOX);

  menu_installed = true;
}

enum script_run_when 
{
  run_on_db_open = 0,  // run script after opening database (default)
  run_on_ui_ready = 1, // run script when UI is ready
  run_on_init = 2,     // run script immediately on plugin load (shortly after IDA starts)
};

static int g_run_when = -1;
static char g_run_script[QMAXPATH];

/* Parse plugin options */
void parse_options()
{
    const char *options = get_plugin_options("IDAPython");
    if ( options == NULL )
        return;
    const char *p = strchr(options, ';');
    if ( p == NULL )
    {
        g_run_when = run_on_db_open;
        qstrncpy(g_run_script, options, sizeof(g_run_script));
    }
    else
    {
        g_run_when = atoi(options);
        qstrncpy(g_run_script, p+1, sizeof(g_run_script));
    }
}

/* we install the menu later because the text version crashes if
add_menu_item is called too early */
static int idaapi menu_installer_cb(void *, int code, va_list)
{
  switch ( code )
  {
    case ui_ready_to_run:
      print_banner();
      install_python_menus();

      if ( g_run_when == run_on_ui_ready )
          IDAPython_RunScript(g_run_script);
      break;

    case ui_database_inited:
      if ( g_run_when == run_on_db_open )
          IDAPython_RunScript(g_run_script);
      break;

    default:
      break;
  }
  return 0;
}

/* Initialize the Python environment */
bool IDAPython_Init(void)
{
    char tmp[MAXSTR+64];
    bool result = true;

    /* Already initialized? */
    if (initialized == 1)
        return true;

    /* Check for the presence of essential files */
    initialized = 0;

    result &= CheckFile("idc.py");
    result &= CheckFile("init.py");
    result &= CheckFile("idaapi.py");
    result &= CheckFile("idautils.py");
    if (!result)
        return false;

#ifdef __LINUX__
    /* Export symbols from libpython to resolve imported module deps */
    qsnprintf(tmp, sizeof(tmp), "libpython%d.%d.so",
              PY_MAJOR_VERSION,
              PY_MINOR_VERSION);
    if (!dlopen(tmp, RTLD_NOLOAD | RTLD_GLOBAL | RTLD_LAZY))
    {
        warning("IDAPython: %s", dlerror());
        return false;
    }
#endif

    /* Start the interpreter */
    Py_Initialize();
    if (!Py_IsInitialized())
    {
        warning("IDAPython: Py_Initialize() failed");
        return false;
    }

    /* Init the SWIG wrapper */
    init_idaapi();
    /* Set IDAPYTHON_VERSION in Python */
    qsnprintf(tmp, sizeof(tmp), "IDAPYTHON_VERSION=(%d, %d, %d, '%s', %d)", \
              VER_MAJOR,
              VER_MINOR,
              VER_PATCH,
              VER_STATUS,
              VER_SERIAL);
  begin_execution();
    PyRun_SimpleString(tmp);
  end_execution();

    /* Pull in the Python side of init */
    qmakepath(tmp, MAXSTR, idadir(PYTHON_DIR_NAME), "init.py", NULL);
    if (!ExecFile(tmp))
    {
        handle_python_error(tmp, sizeof(tmp));
        warning("IDAPython: error executing init.py:\n%s", tmp);
        return false;
    }

    /* Init pywraps (hand made/custom wrapper) */
    if (!init_pywraps())
    {
      warning("IDAPython: init_pywraps() failed!");
      return false;
    }

#ifdef ENABLE_PYTHON_PROFILING
    PyEval_SetTrace(tracefunc, NULL);
#endif

    /* Batch-mode operation: */
    /* A script specified on the command line is run */
    parse_options();
    if ( g_run_when == run_on_init )
        IDAPython_RunScript(g_run_script);

#ifdef PLUGINFIX
    hook_to_notification_point(HT_UI, menu_installer_cb, NULL);
#else
    install_python_menus();
    print_banner();
#endif
    /* Register a RunPythonStatement() function for IDC */
    set_idc_func("RunPythonStatement", idc_runpythonstatement, idc_runpythonstatement_args);

#if IDA_SDK_VERSION >= 540
    /* Enable the CLI by default */
    enable_python_cli(true);
#endif

#if IDA_SDK_VERSION >= 560
    install_extlang(&extlang_python);
#endif

    initialized = 1;

    return true;
}

/* Cleaning up Python */
void IDAPython_Term(void)
{
#ifdef PLUGINFIX
    unhook_from_notification_point(HT_UI, menu_installer_cb, NULL);
#endif
    /* Remove the menu items before termination */
    del_menu_item("File/Load file/Python file...");
    del_menu_item("File/Python file...");
    del_menu_item("File/Python command...");
    del_menu_item("View/Open subviews/Python Scripts");
    menu_installed = false;
#if IDA_SDK_VERSION >= 540
    /* Remove the CLI */
    enable_python_cli(false);
#endif

    /* Remove the extlang */
#if IDA_SDK_VERSION >= 560
    remove_extlang(&extlang_python);
#else
    register_extlang(NULL);
#endif

    /* De-init pywraps */
    deinit_pywraps();
    /* Shut the interpreter down */
    Py_Finalize();

    initialized = 0;
}

/* Plugin init routine */
int idaapi init(void)
{
    if (IDAPython_Init())
        return PLUGIN_KEEP;
    else
        return PLUGIN_SKIP;
}

/* Plugin term routine */
void idaapi term(void)
{
    IDAPython_Term();
}

/* Plugin hotkey entry point */
void idaapi run(int arg)
{
    try
    {
        switch (arg)
        {
        case 0:
            IDAPython_RunScript(NULL);
            break;
            ;;
        case 1:
            IDAPython_RunStatement();
            break;
            ;;
        case 2:
            IDAPython_ScriptBox();
            break;
            ;;
        case 3:
            enable_extlang_python(true);
            break;
            ;;
        case 4:
            enable_extlang_python(false);
            break;
            ;;
        default:
            warning("IDAPython: unknown plugin argument %d", arg);
            break;
            ;;
        }
    }
    catch(...)
    {
        warning("Exception in Python interpreter. Reloading...");
        IDAPython_Term();
        IDAPython_Init();
    }
}

//--------------------------------------------------------------------------
// PLUGIN DESCRIPTION BLOCK
//--------------------------------------------------------------------------
char comment[]       = "IDAPython";
char help[]          = "IDA Python Plugin\n";
char wanted_name[]   = "IDAPython";
char wanted_hotkey[] = "Alt-9";

extern "C"
{
    plugin_t PLUGIN = {
        IDP_INTERFACE_VERSION,
#ifdef PLUGINFIX
        PLUGIN_FIX,    // plugin flags
#else
        0,             // plugin flags
#endif
        init,          // initialize
        term,          // terminate. this pointer may be NULL.
        run,           // invoke plugin
        comment,       // long comment about the plugin
                       // it could appear in the status line
                       // or as a hint
        help,          // multiline help about the plugin
        wanted_name,   // the preferred short name of the plugin
        wanted_hotkey  // the preferred hotkey to run the plugin
    };
}
