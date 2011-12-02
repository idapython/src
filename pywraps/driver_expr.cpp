#include "py_expr.hpp"

#pragma warning(push)
#pragma warning(disable: 4244)

//---------------------------------------------------------------------------
static PyObject *ex_pyw_register_idc_func(PyObject *self, PyObject *args)
{
  char *name, *arg;
  PyObject *py_fp;
  if ( !PyArg_ParseTuple(args, "ssO", &name, &arg, &py_fp) )
    return NULL;
  else
    return PyLong_FromUnsignedLongLong(pyw_register_idc_func(name, arg, py_fp));
}

//---------------------------------------------------------------------------
static PyObject *ex_pyw_unregister_idc_func(PyObject *self, PyObject *args)
{
  unsigned PY_LONG_LONG ctxptr;
  if ( !PyArg_ParseTuple(args, "K", &ctxptr) )
    return NULL;
  return PyLong_FromLong(pyw_unregister_idc_func(ctxptr));
}

static PyObject *ex_py_set_idc_func_ex(PyObject *self, PyObject *pyargs)
{
  const char *name;
  unsigned PY_LONG_LONG fp_ptr;
  const char *args;
  int flags;
  if ( !PyArg_ParseTuple(pyargs, "sKsi", &name, &fp_ptr, &args, &flags) )
    return NULL;
  else
    return PyLong_FromLong(py_set_idc_func_ex(name, fp_ptr, args, flags));
}

//---------------------------------------------------------------------------
static PyObject *ex_py_get_call_idc_func(PyObject *self, PyObject *args)
{
  return PyLong_FromUnsignedLongLong(py_get_call_idc_func());
}

//-------------------------------------------------------------------------
#pragma warning(pop)

//-------------------------------------------------------------------------
static PyMethodDef py_methods_expr[] =
{
  {"pyw_register_idc_func", ex_pyw_register_idc_func, METH_VARARGS, ""},
  {"pyw_unregister_idc_func", ex_pyw_unregister_idc_func, METH_VARARGS, ""},
  {"py_get_call_idc_func", ex_py_get_call_idc_func, METH_VARARGS, ""},
  {"py_set_idc_func_ex", ex_py_set_idc_func_ex, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL} // End of methods
};
DRIVER_INIT_METHODS(expr);
