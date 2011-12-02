#include "py_choose2.hpp"

//-------------------------------------------------------------------------
static PyObject *ex_choose2_find(PyObject *self, PyObject *args)
{
  char *title;
  if ( !PyArg_ParseTuple(args, "s", &title) )
    return NULL;
  else
    return choose2_find(title);
}

//-------------------------------------------------------------------------
static PyObject *ex_choose2_create(PyObject *self, PyObject *args)
{
  PyObject *obj;
  int embedded;
  if ( !PyArg_ParseTuple(args, "Oi", &obj, &embedded) )
    return NULL;
  else
    return PyInt_FromLong(choose2_create(obj, embedded == 1 ? true : false));
}

//-------------------------------------------------------------------------
static PyObject *ex_choose2_activate(PyObject *self, PyObject *args)
{
  PyObject *obj;
  if ( !PyArg_ParseTuple(args, "O", &obj) )
    return NULL;
  
  choose2_activate(obj);
  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
static PyObject *ex_choose2_close(PyObject *self, PyObject *args)
{
  PyObject *obj;
  if ( !PyArg_ParseTuple(args, "O", &obj) )
    return NULL;
  
  choose2_close(obj);
  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
static PyObject *ex_choose2_refresh(PyObject *self, PyObject *args)
{
  PyObject *obj;
  if ( !PyArg_ParseTuple(args, "O", &obj) )
    return NULL;

  choose2_refresh(obj);
  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
static PyObject *ex_choose2_add_command(PyObject *self, PyObject *args)
{
  PyObject *obj;
  char *caption;
  int flags, menu_index, icon;
  if ( !PyArg_ParseTuple(args, "Osiii", &obj, &caption, &flags, &menu_index, &icon) )
    return NULL;
  else
    return PyInt_FromLong(choose2_add_command(obj, caption, flags, menu_index, icon));
}

//-------------------------------------------------------------------------
static PyObject *ex_choose2_get_test_embedded(PyObject *self, PyObject *args)
{
  return PyLong_FromSize_t(choose2_get_test_embedded());
}

//-------------------------------------------------------------------------
static PyObject *ex_choose2_get_embedded(PyObject *self, PyObject *args)
{
  PyObject *obj;
  if ( !PyArg_ParseTuple(args, "O", &obj) )
    return NULL;
  else
    return choose2_get_embedded(obj);
}

//-------------------------------------------------------------------------
static PyObject *ex_choose2_get_embedded_selection(PyObject *self, PyObject *args)
{
  PyObject *obj;
  if ( !PyArg_ParseTuple(args, "O", &obj) )
    return NULL;
  else
    return choose2_get_embedded_selection(obj);
}

//-------------------------------------------------------------------------
static PyMethodDef py_methods_chooser[] =
{
  {"py_choose2_find", ex_choose2_find, METH_VARARGS, ""},
  {"py_choose2_create", ex_choose2_create, METH_VARARGS, ""},
  {"py_choose2_close", ex_choose2_close, METH_VARARGS, ""},
  {"py_choose2_activate", ex_choose2_activate, METH_VARARGS, ""},
  {"py_choose2_refresh", ex_choose2_refresh, METH_VARARGS, ""},
  {"py_choose2_add_command", ex_choose2_add_command, METH_VARARGS, ""},
  {"py_choose2_get_test_embedded", ex_choose2_get_test_embedded, METH_VARARGS, ""},
  {"py_choose2_get_embedded", ex_choose2_get_embedded, METH_VARARGS, ""},
  {"py_choose2_get_embedded_selection", ex_choose2_get_embedded_selection, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL} // End of methods
};
DRIVER_INIT_METHODS(chooser);
