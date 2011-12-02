#include "py_kernwin.hpp"

//-------------------------------------------------------------------------
static PyObject *ex_add_menu_item(PyObject *self, PyObject *args)
{
  const char *menupath, *name, *hotkey;
  PyObject *pyfunc, *pyargs;
  int flags;
  if ( !PyArg_ParseTuple(args, "sssiOO", &menupath, &name, &hotkey, &flags, &pyfunc, &pyargs) )
    return NULL;
  return py_add_menu_item(menupath, name, hotkey, flags, pyfunc, pyargs);
}

//-------------------------------------------------------------------------
static PyObject *ex_del_menu_item(PyObject *self, PyObject *args)
{
  if ( !PyArg_ParseTuple(args, "O", &self) )
    return NULL;
  if ( py_del_menu_item(self) )
    Py_RETURN_TRUE;
  else
    Py_RETURN_FALSE;
}

//-------------------------------------------------------------------------
static PyObject *ex_execute_sync(PyObject *self, PyObject *args)
{
  PyObject *pycall;
  int reqf;
  if ( !PyArg_ParseTuple(args, "Oi", &pycall, &reqf) )
    return NULL;
  return PyInt_FromLong(py_execute_sync(pycall, reqf));
}

//-------------------------------------------------------------------------
static PyObject *ex_add_hotkey(PyObject *self, PyObject *args)
{
  PyObject *pyfunc;
  const char *hotkey;
  if ( !PyArg_ParseTuple(args, "sO", &hotkey, &pyfunc) )
    return NULL;
  else
    return py_add_hotkey(hotkey, pyfunc);
}

//-------------------------------------------------------------------------
static PyObject *ex_del_hotkey(PyObject *self, PyObject *args)
{
  PyObject *pyctx;
  if ( !PyArg_ParseTuple(args, "O", &pyctx) )
    return NULL;
  else
    return PyInt_FromLong(py_del_hotkey(pyctx) ? 1 : 0);
}

//-------------------------------------------------------------------------
static PyObject *ex_execute_ui_request(PyObject *self, PyObject *args)
{
  PyObject *py_list;
  if ( !PyArg_ParseTuple(args, "O", &py_list) )
    return NULL;
  else
    return PyBool_FromLong(py_execute_ui_requests(py_list) ? 1 : 0);
}


//-------------------------------------------------------------------------
static PyMethodDef py_methods_kernwin[] =
{
  {"py_del_menu_item",      ex_del_menu_item,       METH_VARARGS, ""},
  {"py_add_menu_item",      ex_add_menu_item,       METH_VARARGS, ""},
  {"py_execute_sync",       ex_execute_sync,        METH_VARARGS, ""},
  {"py_add_hotkey",         ex_add_hotkey,          METH_VARARGS, ""},
  {"py_del_hotkey",         ex_del_hotkey,          METH_VARARGS, ""},
  {"py_execute_ui_request", ex_execute_ui_request,  METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};
DRIVER_INIT_METHODS(kernwin);