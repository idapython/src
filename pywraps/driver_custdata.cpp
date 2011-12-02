#include "py_custdata.hpp"

//-------------------------------------------------------------------------
static PyObject *ex_register_custom_data_type(PyObject *self, PyObject *args)
{
  PyObject *py_dt;
  if ( !PyArg_ParseTuple(args, "O", &py_dt) )
    return NULL;
  return Py_BuildValue("i", py_register_custom_data_type(py_dt));
}

//-------------------------------------------------------------------------
static PyObject *ex_unregister_custom_data_type(PyObject *self, PyObject *args)
{
  int dtid;
  if ( !PyArg_ParseTuple(args, "i", &dtid) )
    return NULL;
  return Py_BuildValue("i", py_unregister_custom_data_type(dtid));
}

//-------------------------------------------------------------------------
static PyObject *ex_unregister_custom_data_format(PyObject *self, PyObject *args)
{
  int dtid, dfid;
  if ( !PyArg_ParseTuple(args, "ii", &dtid, &dfid) )
    return NULL;
  return Py_BuildValue("i", py_unregister_custom_data_format(dtid, dfid));
}

//-------------------------------------------------------------------------
static PyObject *ex_register_custom_data_format(PyObject *self, PyObject *args)
{
  int dtid;
  PyObject *py_df;
  if ( !PyArg_ParseTuple(args, "iO", &dtid, &py_df) )
    return NULL;
  return Py_BuildValue("i", py_register_custom_data_format(dtid, py_df));
}

//-------------------------------------------------------------------------
static PyObject *ex_get_custom_data_format(PyObject *self, PyObject *args)
{
  int dtid, dfid;
  if ( !PyArg_ParseTuple(args, "ii", &dtid, &dfid) )
    return NULL;
  return py_get_custom_data_format(dtid, dfid);
}

//-------------------------------------------------------------------------
static PyObject *ex_get_custom_data_type(PyObject *self, PyObject *args)
{
  int dtid;
  if ( !PyArg_ParseTuple(args, "i", &dtid) )
    return NULL;
  return py_get_custom_data_type(dtid);
}

//-------------------------------------------------------------------------
static PyMethodDef py_methods_custdata[] =
{
  {"unregister_custom_data_format",  ex_unregister_custom_data_format, METH_VARARGS, ""},
  {"register_custom_data_format", ex_register_custom_data_format, METH_VARARGS, ""},
  {"unregister_custom_data_type", ex_unregister_custom_data_type, METH_VARARGS, ""},
  {"register_custom_data_type", ex_register_custom_data_type, METH_VARARGS, ""},
  {"get_custom_data_format", ex_get_custom_data_format, METH_VARARGS, ""},
  {"get_custom_data_type", ex_get_custom_data_type, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};
//---------------------------------------------------------------------------
class init_custdata_driver_t
{
public:
  init_custdata_driver_t()
  {
    driver_add_methods(py_methods_custdata);
  }
} init_custdata_driver;
