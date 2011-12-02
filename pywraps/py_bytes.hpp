#ifndef __PY_IDA_BYTES__
#define __PY_IDA_BYTES__

//<code(py_bytes)>
//------------------------------------------------------------------------
static bool idaapi py_testf_cb(flags_t flags, void *ud)
{
  PyObject *py_flags = PyLong_FromUnsignedLong(flags);
  PYW_GIL_ENSURE;
  PyObject *result = PyObject_CallFunctionObjArgs((PyObject *) ud, py_flags, NULL);
  PYW_GIL_RELEASE;
  bool ret = result != NULL && PyObject_IsTrue(result);
  Py_XDECREF(result);
  Py_XDECREF(py_flags);
  return ret;
}

//------------------------------------------------------------------------
// Wraps the (next|prev)that()
static ea_t py_npthat(ea_t ea, ea_t bound, PyObject *py_callable, bool next)
{
  if ( !PyCallable_Check(py_callable) )
    return BADADDR;
  else
    return (next ? nextthat : prevthat)(ea, bound, py_testf_cb, py_callable);
}

//---------------------------------------------------------------------------
static int idaapi py_visit_patched_bytes_cb(
      ea_t ea,
      int32 fpos,
      uint32 o,
      uint32 v,
      void *ud)
{
  PYW_GIL_ENSURE;
  PyObject *py_result = PyObject_CallFunction(
    (PyObject *)ud,
    PY_FMT64 "iII",
    pyul_t(ea),
    fpos,
    o,
    v);
  PYW_GIL_RELEASE;

  PyW_ShowCbErr("visit_patched_bytes");
  int ret = (py_result != NULL && PyInt_Check(py_result)) ? PyInt_AsLong(py_result) : 0;
  Py_XDECREF(py_result);
  return ret;
}
//</code(py_bytes)>
//------------------------------------------------------------------------

//<inline(py_bytes)>

//------------------------------------------------------------------------
/*
#<pydoc>
def visit_patched_bytes(ea1, ea2, callable):
    """
    Enumerates patched bytes in the given range and invokes a callable
    @param ea1: start address
    @param ea2: end address
    @param callable: a Python callable with the following prototype:
                     callable(ea, fpos, org_val, patch_val).
                     If the callable returns non-zero then that value will be
                     returned to the caller and the enumeration will be
                     interrupted.
    @return: Zero if the enumeration was successful or the return
             value of the callback if enumeration was interrupted.
    """
    pass
#</pydoc>
*/
static int py_visit_patched_bytes(ea_t ea1, ea_t ea2, PyObject *py_callable)
{
  if ( !PyCallable_Check(py_callable) )
    return 0;
  else
    return visit_patched_bytes(ea1, ea2, py_visit_patched_bytes_cb, py_callable);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def nextthat(ea, maxea, callable):
    """
    Find next address with a flag satisfying the function 'testf'.
    Start searching from address 'ea'+1 and inspect bytes up to 'maxea'.
    maxea is not included in the search range.

    @param callable: a Python callable with the following prototype:
                     callable(flags). Return True to stop enumeration.
    @return: the found address or BADADDR.
    """
    pass
#</pydoc>
*/
static ea_t py_nextthat(ea_t ea, ea_t maxea, PyObject *callable)
{
  return py_npthat(ea, maxea, callable, true);
}

//---------------------------------------------------------------------------
static ea_t py_prevthat(ea_t ea, ea_t minea, PyObject *callable)
{
  return py_npthat(ea, minea, callable, false);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def get_many_bytes(ea, size):
    """
    Get the specified number of bytes of the program into the buffer.
    @param ea: program address
    @param size: number of bytes to return
    @return: None or the string buffer
    """
    pass
#</pydoc>
*/
static PyObject *py_get_many_bytes(ea_t ea, unsigned int size)
{
  do
  {
    if ( size <= 0 )
      break;

    // Allocate memory via Python
    PyObject *py_buf = PyString_FromStringAndSize(NULL, Py_ssize_t(size));
    if ( py_buf == NULL )
      break;

    // Read bytes
    bool ok = get_many_bytes(ea, PyString_AsString(py_buf), size);

    // If failed, dispose the Python string
    if ( !ok )
    {
      Py_DECREF(py_buf);

      py_buf = Py_None;
      Py_INCREF(py_buf);
    }

    return py_buf;
  } while ( false );
  Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
/*
#<pydoc>
def get_ascii_contents2(ea, len, type, flags = ACFOPT_ASCII):
  """
  Get contents of ascii string
  This function returns the displayed part of the string
  It works even if the string has not been created in the database yet.

  @param ea: linear address of the string
  @param len: length of the string in bytes (including terminating 0)
  @param type: type of the string
  @param flags: combination of ACFOPT_...
  @return: string contents (not including terminating 0) or None
  """
  pass
#</pydoc>
*/
static PyObject *py_get_ascii_contents2(
    ea_t ea,
    size_t len,
    int32 type,
    int flags = ACFOPT_ASCII)
{
  char *buf = (char *)qalloc(len+1);
  if ( buf == NULL )
    return NULL;

  size_t used_size;
  if ( !get_ascii_contents2(ea, len, type, buf, len+1, &used_size) )
  {
    qfree(buf);
    Py_RETURN_NONE;
  }
  if ( type == ASCSTR_C && used_size > 0 && buf[used_size-1] == '\0' )
    used_size--;
  PyObject *py_buf = PyString_FromStringAndSize((const char *)buf, used_size);
  qfree(buf);
  return py_buf;
}
//---------------------------------------------------------------------------
/*
#<pydoc>
def get_ascii_contents(ea, len, type):
  """
  Get contents of ascii string
  This function returns the displayed part of the string
  It works even if the string has not been created in the database yet.

  @param ea: linear address of the string
  @param len: length of the string in bytes (including terminating 0)
  @param type: type of the string
  @return: string contents (not including terminating 0) or None
  """
  pass
#</pydoc>
*/
static PyObject *py_get_ascii_contents(
    ea_t ea,
    size_t len,
    int32 type)
{
  return py_get_ascii_contents2(ea, len, type);
}
//</inline(py_bytes)>

#endif
