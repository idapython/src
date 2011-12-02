#include "py_nalt.hpp"

//-------------------------------------------------------------------------
static PyObject *ex_get_switch_info_ex(PyObject *self, PyObject *args)
{
  pyul_t ea;
  if ( !PyArg_ParseTuple(args, PY_FMT64, &ea) )
    return NULL;
  return py_get_switch_info_ex(ea_t(ea));
}

//-------------------------------------------------------------------------
static PyMethodDef py_methods_nalt[] =
{
  {"get_switch_info_ex",  ex_get_switch_info_ex, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}
};
DRIVER_INIT_METHODS(nalt);
