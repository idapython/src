#include "py_custview.hpp"

//-------------------------------------------------------------------------
static PyObject *ex_install_command_interpreter(PyObject *self, PyObject *args)
{
  PyObject *py_obj;
  if ( !PyArg_ParseTuple(args, "O", &py_obj) )
    return NULL;
  return PyInt_FromLong(py_install_command_interpreter(py_obj));
}

//-------------------------------------------------------------------------
static PyObject *ex_remove_command_interpreter(PyObject *self, PyObject *args)
{
  int cli_idx;
  if ( !PyArg_ParseTuple(args, "i", &cli_idx) )
    return NULL;
  py_remove_command_interpreter(cli_idx);
  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
static PyMethodDef py_methods_cli[] =
{
  {"install_command_interpreter",  ex_install_command_interpreter, METH_VARARGS, ""},
  {"remove_command_interpreter",  ex_remove_command_interpreter, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}
};
DRIVER_INIT_METHODS(cli);