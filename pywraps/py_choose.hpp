#ifndef __PY_CHOOSE__
#define __PY_CHOOSE__

//---------------------------------------------------------------------------
//<inline(py_kernwin)>
//---------------------------------------------------------------------------
uint32 idaapi choose_sizer(void *self)
{
  PYW_GIL_GET;
  newref_t pyres(PyObject_CallMethod((PyObject *)self, "sizer", ""));
  return PyInt_AsLong(pyres.o);
}

//---------------------------------------------------------------------------
char *idaapi choose_getl(void *self, uint32 n, char *buf)
{
  PYW_GIL_GET;
  newref_t pyres(
          PyObject_CallMethod(
                  (PyObject *)self,
                  "getl",
                  "l",
                  n));

  const char *res;
  if (pyres == NULL || (res = PyString_AsString(pyres.o)) == NULL )
    qstrncpy(buf, "<Empty>", MAXSTR);
  else
    qstrncpy(buf, res, MAXSTR);
  return buf;
}

//---------------------------------------------------------------------------
void idaapi choose_enter(void *self, uint32 n)
{
  PYW_GIL_GET;
  newref_t res(PyObject_CallMethod((PyObject *)self, "enter", "l", n));
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
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t pytitle(PyObject_GetAttrString((PyObject *)self, "title"));
  const char *title = pytitle != NULL ? PyString_AsString(pytitle.o) : "Choose";

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

  return r;
}
//</inline(py_kernwin)>

#endif // __PY_CHOOSE__
