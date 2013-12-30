#ifndef __PY_LOADER___
#define __PY_LOADER___

//------------------------------------------------------------------------
//<inline(py_loader)>

//------------------------------------------------------------------------
/*
#<pydoc>
def mem2base(mem, ea, fpos):
    """
    Load database from the memory.
    @param mem: the buffer
    @param ea: start linear addresses
    @param fpos: position in the input file the data is taken from.
                 if == -1, then no file position correspond to the data.
    @return:
        - Returns zero if the passed buffer was not a string
        - Otherwise 1 is returned
    """
    pass
#</pydoc>
*/
static int py_mem2base(PyObject *py_mem, ea_t ea, long fpos = -1)
{
  Py_ssize_t len;
  char *buf;
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyString_AsStringAndSize(py_mem, &buf, &len) == -1 )
      return 0;
  }

  return mem2base((void *)buf, ea, ea+len, fpos);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def load_plugin(name):
    """
    Loads a plugin
    @return:
        - None if plugin could not be loaded
        - An opaque object representing the loaded plugin
    """
    pass
#</pydoc>
*/
static PyObject *py_load_plugin(const char *name)
{
  plugin_t *r = load_plugin(name);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( r == NULL )
    Py_RETURN_NONE;
  else
    return PyCObject_FromVoidPtr(r, NULL);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def run_plugin(plg):
    """
    Runs a plugin
    @param plg: A plugin object (returned by load_plugin())
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_run_plugin(PyObject *plg, int arg)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCObject_Check(plg) )
  {
    return false;
  }
  else
  {
    plugin_t *p = (plugin_t *)PyCObject_AsVoidPtr(plg);
    bool rc;
    Py_BEGIN_ALLOW_THREADS;
    rc = run_plugin(p, arg);
    Py_END_ALLOW_THREADS;
    return rc;
  }
}

//</inline(py_loader)>

#endif
