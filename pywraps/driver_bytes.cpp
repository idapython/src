#include "py_bytes.hpp"

//--------------------------------------------------------------------------
static PyObject *ex_nextthat(PyObject *self, PyObject *args)
{
  PyObject *callback;
  pyul_t addr, bound;
  if ( !PyArg_ParseTuple(args, PY_FMT64 PY_FMT64 "O", &addr, &bound, &callback) )
    return NULL;
  return Py_BuildValue("i", py_nextthat(pyul_t(addr), pyul_t(bound), callback));
}

//--------------------------------------------------------------------------
static PyMethodDef py_methods_bytes[] =
{
  {"nextthat",  ex_nextthat, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}
};
DRIVER_INIT_METHODS(bytes);