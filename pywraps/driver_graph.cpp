#include "py_graph.hpp"

//--------------------------------------------------------------------------
//py_choose2_t *last_c2 = NULL;
static PyObject *ex_graph_show(PyObject * /*self*/, PyObject *args)
{
  PyObject *obj;
  if ( !PyArg_ParseTuple(args, "O", &obj) )
    return NULL;

  py_graph_t *ret = py_graph_t::Show(obj);
  return PyBool_FromLong(ret == NULL ? 0 : 1);
}

//--------------------------------------------------------------------------
static PyObject *ex_graph_refresh(PyObject * /*self*/, PyObject *args)
{
  PyObject *obj;
  if ( !PyArg_ParseTuple(args, "O", &obj) )
    return NULL;
  py_graph_t::Refresh(obj);
  Py_RETURN_NONE;
}

//--------------------------------------------------------------------------
static PyObject *ex_graph_addcmd(PyObject *self, PyObject *args)
{
  PyObject *obj;
  const char *title, *hotkey;
  if ( !PyArg_ParseTuple(args, "Oss", &obj, &title, &hotkey) )
    return NULL;
  Py_ssize_t r = py_graph_t::AddCommand(obj, title, hotkey);
  return Py_BuildValue("n", r);
}

//--------------------------------------------------------------------------
static PyMethodDef py_methods_graph[] =
{
  {"show",  ex_graph_show, METH_VARARGS, ""},
  {"refresh", ex_graph_refresh, METH_VARARGS, ""},
  {"addcmd", ex_graph_addcmd, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};
DRIVER_INIT_METHODS(graph);