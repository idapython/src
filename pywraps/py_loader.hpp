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
static int py_mem2base(PyObject *py_mem, ea_t ea, qoff64_t fpos = -1)
{
  Py_ssize_t len;
  char *buf;
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyBytes_AsStringAndSize(py_mem, &buf, &len) == -1 )
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
  if ( qfileexist(name) )
    prepare_programmatic_plugin_load(name);
  plugin_t *r = load_plugin(name);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  prepare_programmatic_plugin_load(nullptr);
  if ( r == nullptr )
    Py_RETURN_NONE;
  else
    return PyCapsule_New(r, VALID_CAPSULE_NAME, nullptr);
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
static bool py_run_plugin(PyObject *plg, size_t arg)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCapsule_IsValid(plg, VALID_CAPSULE_NAME) )
  {
    return false;
  }
  else
  {
    plugin_t *p = (plugin_t *) PyCapsule_GetPointer(plg, VALID_CAPSULE_NAME);
    bool rc;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    rc = run_plugin(p, arg);
    SWIG_PYTHON_THREAD_END_ALLOW;
    return rc;
  }
}

//------------------------------------------------------------------------
static bool py_load_and_run_plugin(const char *name, size_t arg)
{
  if ( qfileexist(name) )
    prepare_programmatic_plugin_load(name);
  bool rc = load_and_run_plugin(name, arg);
  prepare_programmatic_plugin_load(nullptr);
  return rc;
}

//-------------------------------------------------------------------------
static PyObject *py_extract_module_from_archive(const char *fname, bool is_remote=false)
{
  bool ok = fname != nullptr;
  char *temp_file_ptr = nullptr;
  char fname_buf[QMAXPATH];
  if ( ok )
  {
    qstrncpy(fname_buf, fname, sizeof(fname_buf));
    ok = extract_module_from_archive(
            fname_buf,
            sizeof(fname_buf),
            &temp_file_ptr,
            is_remote);
  }
  return Py_BuildValue("(ss)", ok ? fname_buf : nullptr, ok ? temp_file_ptr : nullptr);
}

//</inline(py_loader)>

#endif
