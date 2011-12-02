#ifndef __PY_CHOOSE__
#define __PY_CHOOSE__

//---------------------------------------------------------------------------
//<inline(py_kernwin)>
//---------------------------------------------------------------------------
uint32 idaapi choose_sizer(void *self)
{
  PyObject *pyres;
  uint32 res;

  PYW_GIL_ENSURE;
  pyres = PyObject_CallMethod((PyObject *)self, "sizer", "");
  PYW_GIL_RELEASE;

  res = PyInt_AsLong(pyres);
  Py_DECREF(pyres);
  return res;
}

//---------------------------------------------------------------------------
char *idaapi choose_getl(void *self, uint32 n, char *buf)
{
  PYW_GIL_ENSURE;
  PyObject *pyres = PyObject_CallMethod(
    (PyObject *)self,
    "getl",
    "l",
    n);
  PYW_GIL_RELEASE;

  const char *res;
  if (pyres == NULL || (res = PyString_AsString(pyres)) == NULL )
    qstrncpy(buf, "<Empty>", MAXSTR);
  else
    qstrncpy(buf, res, MAXSTR);

  Py_XDECREF(pyres);
  return buf;
}

//---------------------------------------------------------------------------
void idaapi choose_enter(void *self, uint32 n)
{
  PYW_GIL_ENSURE;
  Py_XDECREF(PyObject_CallMethod((PyObject *)self, "enter", "l", n));
  PYW_GIL_RELEASE;
}

//---------------------------------------------------------------------------
uint32 choose_choose(
    void *self,
    int flags,
    int x0,int y0,
    int x1,int y1,
    int width,
    int deflt,
    int icon)
{
  PyObject *pytitle = PyObject_GetAttrString((PyObject *)self, "title");
  const char *title = pytitle != NULL ? PyString_AsString(pytitle) : "Choose";

  int r = choose(
    flags,
    x0, y0,
    x1, y1,
    self,
    width,
    choose_sizer,
    choose_getl,
    title,
    icon,
    deflt,
    NULL, /* del */
    NULL, /* inst */
    NULL, /* update */
    NULL, /* edit */
    choose_enter,
    NULL, /* destroy */
    NULL, /* popup_names */
    NULL);/* get_icon */
  Py_XDECREF(pytitle);
  return r;
}
//</inline(py_kernwin)>

#endif // __PY_CHOOSE__