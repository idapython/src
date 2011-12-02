#include "py_notifywhen.hpp"

//-------------------------------------------------------------------------
static PyObject *ex_notify_when(PyObject *self, PyObject *args)
{
  int when;
  PyObject *py_callable;
  if ( !PyArg_ParseTuple(args, "IO", &when, &py_callable) )
    return NULL;
  return Py_BuildValue("i", notify_when(when, py_callable));
}

//-------------------------------------------------------------------------
static PyMethodDef py_methods_nw[] =
{
  {"notify_when",  ex_notify_when, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};
DRIVER_INIT_METHODS(nw);

#define DRIVER_INIT
int driver_init()
{
  bool ok = pywraps_nw_init();
  if ( !ok )
    return PLUGIN_SKIP;
  pywraps_nw_notify(NW_INITIDA_SLOT);
  return PLUGIN_KEEP;
}

#define DRIVER_TERM
void driver_term()
{
  pywraps_nw_notify(NW_TERMIDA_SLOT);
  pywraps_nw_term();
}
