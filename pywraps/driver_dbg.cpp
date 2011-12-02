#include "py_dbg.hpp"

//-------------------------------------------------------------------------
static PyObject *ex_getthreadsregbase(PyObject * /*self*/, PyObject *args)
{
  PyObject *py_tid, *py_sreg_value;
  if ( !PyArg_ParseTuple(args, "OO", &py_tid, &py_sreg_value) )
    return NULL;
  return dbg_get_thread_sreg_base(py_tid, py_sreg_value);
}

//-------------------------------------------------------------------------
static PyObject *ex_readmemory(PyObject * /*self*/, PyObject *args)
{
  PyObject *py_ea, *py_size;
  if ( !PyArg_ParseTuple(args, "OO", &py_ea, &py_size) )
    return NULL;
  return dbg_read_memory(py_ea, py_size);
}

//-------------------------------------------------------------------------
static PyObject *ex_writememory(PyObject * /*self*/, PyObject *args)
{
  PyObject *py_ea, *py_buf;
  if ( !PyArg_ParseTuple(args, "OO", &py_ea, &py_buf) )
    return NULL;
  return dbg_write_memory(py_ea, py_buf);
}

//-------------------------------------------------------------------------
static PyObject *ex_getmeminfo(PyObject * /*self*/, PyObject *args)
{
  return dbg_get_memory_info();
}

//-------------------------------------------------------------------------
static PyObject *ex_getregs(PyObject *self, PyObject *args)
{
  return dbg_get_registers();
}

//-------------------------------------------------------------------------
static PyObject *ex_appcall(PyObject * /*self*/, PyObject *args)
{
  PyObject *app_args, *type, *fields;
  int func_ea, tid;
  if ( !PyArg_ParseTuple(args, "iiOOO", &func_ea, &tid, &type, &fields, &app_args) )
    return NULL;
  return py_appcall(func_ea, tid, type, fields, app_args);
}

//-------------------------------------------------------------------------
static PyObject *ex_pytoidc(
  PyObject *self,
  PyObject *args)
{
  if ( !PyArg_ParseTuple(args, "O", &self) )
    return NULL;
  idc_value_t v;
  int sn = 0;
  if ( pyvar_to_idcvar(self, &v, &sn) < CIP_OK )
    Py_RETURN_NONE;
  Py_RETURN_TRUE;
}

//-------------------------------------------------------------------------
static PyMethodDef py_methods_dbg[] =
{
  {"getregs",  ex_getregs, METH_VARARGS, ""},
  {"getmeminfo", ex_getmeminfo, METH_VARARGS, ""},
  {"readmemory", ex_readmemory, METH_VARARGS, ""},
  {"writememory", ex_writememory, METH_VARARGS, ""},
  {"getthreadsregbase", ex_getthreadsregbase, METH_VARARGS, ""},
  {"appcall", ex_appcall, METH_VARARGS, ""},
  {"pytoidc", ex_pytoidc, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};
DRIVER_INIT_METHODS(dbg);