//------------------------------------------------------------
// IDAPython - Python plugin for Interactive Disassembler Pro
//
// Copyright (c) 2004-2008 Gergely Erdelyi <dyce@d-dome.net>
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
#define VER_STATUS "alpha"

#define IDAPYTHON_RUNFILE      0
#define IDAPYTHON_RUNSTATEMENT 1
#define IDAPYTHON_SCRIPTBOX    2

#define IDAPYTHON_DATA_STATEMENT 0


void init_idaapi(void);
void idaapi run(int arg);

static int initialized = 0;


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

/* Simple Python statement runner function for IDC */
static const char idc_runpythonstatement_args[] = { VT_STR, 0 };
static error_t idaapi idc_runpythonstatement(value_t *argv, value_t *res)
{
	res->num = PyRun_SimpleString(argv[0].str);
	return eOk;
}


/* QuickFix for the FILE* incompatibility problem */
int ExecFile(char *FileName)
{
	PyObject* PyFileObject = PyFile_FromString(FileName, "r");

	if (!PyFileObject)
	{
		return 0;
	}

	if (PyRun_SimpleFile(PyFile_AsFile(PyFileObject), FileName) == 0)
 	{
		Py_DECREF(PyFileObject);
		return 1;
	}
	else
	{
		Py_DECREF(PyFileObject);
		return 0;
	}
}

/* Check for the presence of a file in IDADIR/python */
bool CheckFile(char *filename)
{
	char filepath[MAXSTR+1];

#if IDP_INTERFACE_VERSION >= 75
	qmakepath(filepath, MAXSTR, idadir(NULL), "python", filename, NULL);
#elif IDP_INTERFACE_VERSION >= 69
	qmakepath(filepath, idadir(NULL), "python", filename, NULL);
#else
	qmakepath(filepath, idadir(), "python", filename, NULL);
#endif

	if (!qfileexist(filepath))
	{
		warning("IDAPython: Missing required file %s", filename);
		return false;
	}

	return true;
}

/* Execute the Python script from the plugin */
/* Default hotkey: Alt-9 */
void IDAPython_RunScript(char *script)
{
	char statement[MAXSTR+32];
	char slashpath[MAXSTR+1];
	char *scriptpath;

	int i;

	if (script)
	{
		scriptpath = script;
	}
	else
	{
		scriptpath = askfile_c(0, "*.py", "Python file to run");

		if (!scriptpath)
		{
			return;
		}
	}

	/* Make a copy of the path with '\\' => '/' */
	for (i=0; scriptpath[i]; i++)
	{
		if (scriptpath[i] == '\\')
		{
			slashpath[i] = '/';
		}
		else
		{
			slashpath[i] = scriptpath[i];
		}
	}

	slashpath[i] = '\0';

	/* Add the script't path to sys.path */
	snprintf(statement, sizeof(statement), "runscript(\"%s\")", slashpath);
	PyRun_SimpleString(statement);

	/* Error handling */
	if (PyErr_Occurred())
	{
		PyErr_Print();
	}

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
	{
		statement[0] = '\0';
	}

	if (asktext(sizeof(statement), statement, statement, "Enter Python expressions"))
	{
		PyRun_SimpleString(statement);
		/* Store the statement to the database */
		history.supset(IDAPYTHON_DATA_STATEMENT, statement);
	}
}

/* History of previously executed scripts */
/* Default hotkey: Alt-7 */
void IDAPython_ScriptBox(void)
{
	PyObject *module;
	PyObject *dict;
	PyObject *scriptbox;
	PyObject *pystr;

	/* Get globals() */
	/* These two should never fail */
	module = PyImport_AddModule("__main__");
	dict = PyModule_GetDict(module);

	scriptbox = PyDict_GetItemString(dict, "ScriptBox_instance");

	if (!scriptbox)
	{
		warning("INTERNAL ERROR: ScriptBox_instance missing! Broken init.py?");
		return;
	}

	pystr = PyObject_CallMethod(scriptbox, "run", "");

	if (pystr)
	{
		/* If the return value is string use it as path */
		if (PyObject_TypeCheck(pystr, &PyString_Type))
		{
			ExecFile(PyString_AsString(pystr));
		}
		Py_DECREF(pystr);
	}
	else
	{
		/* Print the exception info */
		if (PyErr_Occurred())
		{
			PyErr_Print();
		}
	}
}

bool idaapi IDAPython_Menu_Callback(void *ud)
{
	run((int)ud);
	return true;
}

/* Compile callback for Python external language evaluator */
bool idaapi IDAPython_extlang_compile(const char *name,
				      ea_t current_ea,
				      const char *expr,
				      char *errbuf,
				      size_t errbufsize)
{
  qstrncpy(errbuf, "evaluation error", errbufsize);
  return false;
}

/* Run callback for Python external language evaluator */
bool idaapi IDAPython_extlang_run(const char *name,
				  int nargs,
				  const idc_value_t args[],
				  idc_value_t *result,
				  char *errbuf,
				  size_t errbufsize)
{
  qstrncpy(errbuf, "evaluation error", errbufsize);
  return false;
}


/* Calculator callback for Python external language evaluator */
bool idaapi IDAPython_extlang_calcexpr(ea_t current_ea,
				      const char *expr,
				      idc_value_t *rv,
				      char *errbuf,
				      size_t errbufsize)
{
  PyObject *result;
  PyObject *ptype, *pvalue, *ptraceback;
  PyObject *module = PyImport_AddModule("__main__");
  double dresult;

  if (module == NULL)
    return false;

  PyObject *globals = PyModule_GetDict(module);

  result = PyRun_String(expr, Py_eval_input, globals, globals);

  if (result == NULL)
    {
      /* Return a formatted error or just print it to the console */
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
	    {
	      PyErr_Print();
	    }
	}
      return false;
    }

  VarFree(rv);

  if (PyInt_Check(result))
    {
      rv->num = PyInt_AsLong(result);
      rv->vtype = VT_LONG;
      Py_XDECREF(result);
      return true;
    }

  if (PyString_Check(result))
    {
      rv->str = (char *)qalloc(PyString_Size(result)+1);
      if (!rv->str)
	{
	  return false;
	}
      strcpy(rv->str, PyString_AsString(result));
      rv->vtype = VT_STR;
      Py_XDECREF(result);
      return true;
    }

  if (PyFloat_Check(result))
    {
      dresult = PyFloat_AsDouble(result);
      ieee_realcvt((void *)&dresult, rv->e, 3);
      rv->vtype = VT_FLOAT;
      Py_XDECREF(result);
      return true;
    }

  return false;
}

extlang_t extlang_python =
  {
    sizeof(extlang_t),
    0,
    "Python",
    IDAPython_extlang_compile,
    IDAPython_extlang_run,
    IDAPython_extlang_calcexpr
  };

void enable_extlang_python(bool enable)
{
  if (enable)
    {
      register_extlang(&extlang_python);
    }
  else
    {
      register_extlang(NULL);
    }
}

#if IDA_SDK_VERSION >= 540
/* Execute a line in the Python CLI */
bool idaapi IDAPython_cli_execute_line(const char *line)
{
  PyRun_SimpleString(line);
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
    {
      install_command_interpreter(&cli_python);
    }
  else
    {
      remove_command_interpreter(&cli_python);
    }
}
#endif

/* Initialize the Python environment */
bool IDAPython_Init(void)
{
	char *options;
	char tmp[MAXSTR+64];
	char *initpath;
	bool result = 1;

	/* Already initialized? */
	if (initialized == 1)
	{
		return true;
	}

	/* Check for the presence of essential files */
	initialized = 0;

	result &= CheckFile("idc.py");
	result &= CheckFile("init.py");
	result &= CheckFile("idaapi.py");
	result &= CheckFile("idautils.py");

	if (!result)
	{
		return false;
	}

	/* Start the interpreter */
	Py_Initialize();

	if (!Py_IsInitialized())
	{
		warning("IDAPython: Py_Initialize() failed");
		return false;
	}

	/* Init the SWIG wrapper */
	init_idaapi();

	sprintf(tmp, "IDAPYTHON_VERSION=(%d, %d, %d, '%s', %d)", \
			VER_MAJOR,
			VER_MINOR,
			VER_PATCH,
			VER_STATUS,
			VER_SERIAL);

	PyRun_SimpleString(tmp);

#if IDP_INTERFACE_VERSION >= 75
	qmakepath(tmp, MAXSTR, idadir("python"), "init.py", NULL);
#elif IDP_INTERFACE_VERSION >= 69
	qmakepath(tmp, idadir("python"), "init.py", NULL);
#else
	qmakepath(tmp, idadir(), "python", "init.py", NULL);
#endif

	/* Pull in the Python side of init */
	if (!ExecFile(tmp))
	{
		warning("IDAPython: error executing init.py");
		return false;
	}

#ifdef ENABLE_PYTHON_PROFILING
	PyEval_SetTrace(tracefunc, NULL);
#endif

	/* Batch-mode operation: */
	/* A script specified on the command line is run */
	options = (char *)get_plugin_options("IDAPython");

	if (options)
	{
		IDAPython_RunScript(options);
	}

	/* Add menu items for all the functions */
	/* Different paths are used for the GUI version */
	result = add_menu_item("File/IDC command...", "P~y~thon command...",
					"Alt-8", SETMENU_APP,
					(menu_item_callback_t *)IDAPython_Menu_Callback,
					(void *)IDAPYTHON_RUNSTATEMENT);

	result = add_menu_item("File/Load file/IDC file...", "P~y~thon file...",
					"Alt-9", SETMENU_APP,
					(menu_item_callback_t *)IDAPython_Menu_Callback,
					(void *)IDAPYTHON_RUNFILE);

	if (!result)
	{
		add_menu_item("File/IDC command...", "P~y~thon file...",
					"Alt-9", SETMENU_APP,
					(menu_item_callback_t *)IDAPython_Menu_Callback,
					(void *)IDAPYTHON_RUNFILE);
	}

	result = add_menu_item("View/Open subviews/Show strings", "Python S~c~ripts",
					"Alt-7", SETMENU_APP,
					(menu_item_callback_t *)IDAPython_Menu_Callback,
					(void *)IDAPYTHON_SCRIPTBOX);

	if (!result)
	{
		add_menu_item("View/Open subviews/Problems", "Python S~c~ripts",
						"Alt-7", SETMENU_APP,
						(menu_item_callback_t *)IDAPython_Menu_Callback,
						(void *)IDAPYTHON_SCRIPTBOX);
	}

	/* Register a RunPythonStatement() function for IDC */
	set_idc_func("RunPythonStatement", idc_runpythonstatement, idc_runpythonstatement_args);

#if IDA_SDK_VERSION >= 540
  	/* Enable the CLI by default */
	enable_python_cli(true);
#endif

	initialized = 1;

	return true;
}

/* Cleaning up Python */
void IDAPython_Term(void)
{
	/* Remove the menu items before termination */
	del_menu_item("File/Load file/Python file...");
	del_menu_item("File/Python file...");
	del_menu_item("File/Python command...");
	del_menu_item("View/Open subviews/Python Scripts");

#if IDA_SDK_VERSION >= 540
  	/* Remove the CLI */
	enable_python_cli(false);
#endif

	/* Remove the extlang */
	register_extlang(NULL);

	/* Shut the interpreter down */
	Py_Finalize();

	initialized = 0;
}

/* Plugin init routine */
int idaapi init(void)
{
	if (IDAPython_Init())
	{
		return PLUGIN_KEEP;
	}
	else
	{
		return PLUGIN_SKIP;
	}
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
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
}
