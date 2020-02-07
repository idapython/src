#ifndef __PY_IDA_BYTES__
#define __PY_IDA_BYTES__

//<code(py_bytes)>
//------------------------------------------------------------------------
static bool idaapi py_testf_cb(flags_t flags, void *ud)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_flags(PyLong_FromUnsignedLong(flags));
  newref_t result(PyObject_CallFunctionObjArgs((PyObject *) ud, py_flags.o, NULL));
  return result != NULL && PyObject_IsTrue(result.o);
}

//------------------------------------------------------------------------
// Wraps the (next|prev)that()
static ea_t py_npthat(ea_t ea, ea_t bound, PyObject *py_callable, bool next)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCallable_Check(py_callable) )
    return BADADDR;
  else
    return (next ? next_that : prev_that)(ea, bound, py_testf_cb, py_callable);
}

//---------------------------------------------------------------------------
static int idaapi py_visit_patched_bytes_cb(
        ea_t ea,
        qoff64_t fpos,
        uint64 o,
        uint64 v,
        void *ud)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_result(
          PyObject_CallFunction(
                  (PyObject *)ud,
                  PY_BV_EA "LKK",
                  bvea_t(ea),
                  fpos,
                  o,
                  v));
  PyW_ShowCbErr("visit_patched_bytes");
  return (py_result != NULL && IDAPyInt_Check(py_result.o)) ? IDAPyInt_AsLong(py_result.o) : 0;
}

//-------------------------------------------------------------------------
static void ida_bytes_term(void) {}

//-------------------------------------------------------------------------
static void clear_custom_data_types_and_formats();
static void ida_bytes_closebase(void)
{
  clear_custom_data_types_and_formats();
}

//-------------------------------------------------------------------------
static bool py_do_get_bytes(
        PyObject **out_py_bytes,
        PyObject **out_py_mask,
        ea_t ea,
        unsigned int size,
        int gmb_flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool has_mask = out_py_mask != NULL;
  do
  {
    if ( size <= 0 )
      break;

    // Allocate memory via Python
    newref_t py_bytes(IDAPyStr_FromUTF8AndSize(NULL, Py_ssize_t(size)));
    if ( py_bytes == NULL )
      break;

    bytevec_t mask;
    if ( has_mask )
      mask.resize((size + 7) / 8, 0);

    // Read bytes
    int code = get_bytes(IDAPyBytes_AsString(py_bytes.o),
                         size,
                         ea,
                         gmb_flags,
                         has_mask ? mask.begin() : NULL);
    if ( code < 0 )
      break;

    // note: specify size, as '0' bytes would otherwise cut the mask short
    if ( has_mask )
    {
      newref_t py_mask(IDAPyStr_FromUTF8AndSize(
                               (const char *) mask.begin(),
                               mask.size()));
      if ( py_mask == NULL )
        break;
      py_mask.incref();
      *out_py_mask = py_mask.o;
    }

    py_bytes.incref();
    *out_py_bytes = py_bytes.o;
    return true;
  } while ( false );
  return false;
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
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCallable_Check(py_callable) )
    return 0;
  else
    return visit_patched_bytes(ea1, ea2, py_visit_patched_bytes_cb, py_callable);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def next_that(ea, maxea, callable):
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
static ea_t py_next_that(ea_t ea, ea_t maxea, PyObject *callable)
{
  return py_npthat(ea, maxea, callable, true);
}

//---------------------------------------------------------------------------
static ea_t py_prev_that(ea_t ea, ea_t minea, PyObject *callable)
{
  return py_npthat(ea, minea, callable, false);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def get_bytes(ea, size):
    """
    Get the specified number of bytes of the program.
    @param ea: program address
    @param size: number of bytes to return
    @return: the bytes (as a str), or None in case of failure
    """
    pass
#</pydoc>
*/
static PyObject *py_get_bytes(ea_t ea, unsigned int size, int gmb_flags=GMB_READALL)
{
  PyObject *py_bytes = NULL;
  if ( py_do_get_bytes(&py_bytes, NULL, ea, size, gmb_flags) )
    return py_bytes;
  else
    Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
/*
#<pydoc>
def get_bytes_and_mask(ea, size, mask):
    """
    Get the specified number of bytes of the program, and a bitmask
    specifying what bytes are defined and what bytes are not.
    @param ea: program address
    @param size: number of bytes to return
    @return: a tuple (bytes, mask), or None in case of failure.
             Both 'bytes' and 'mask' are 'str' instances.
    """
    pass
#</pydoc>
*/
static PyObject *py_get_bytes_and_mask(ea_t ea, unsigned int size, int gmb_flags=GMB_READALL)
{
  PyObject *py_bytes = NULL;
  PyObject *py_mask = NULL;
  if ( py_do_get_bytes(&py_bytes, &py_mask, ea, size, gmb_flags) )
    return Py_BuildValue("(OO)", py_bytes, py_mask);
  else
    Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
/*
#<pydoc>
# Conversion options for get_strlit_contents():
STRCONV_ESCAPE   = 0x00000001 # convert non-printable characters to C escapes (\n, \xNN, \uNNNN)

def get_strlit_contents(ea, len, type, flags = 0):
  """
  Get bytes contents at location, possibly converted.
  It works even if the string has not been created in the database yet.

  Note that this will <b>always</b> return a simple string of bytes
  (i.e., a 'str' instance), and not a string of unicode characters.

  If you want auto-conversion to unicode strings (that is: real strings),
  you should probably be using the idautils.Strings class.

  @param ea: linear address of the string
  @param len: length of the string in bytes (including terminating 0)
  @param type: type of the string. Represents both the character encoding,
               <u>and</u> the 'type' of string at the given location.
  @param flags: combination of STRCONV_..., to perform output conversion.
  @return: a bytes-filled str object.
  """
  pass
#</pydoc>
*/
static PyObject *py_get_strlit_contents(
        ea_t ea,
        PyObject *py_len,
        int32 type,
        int flags = 0)
{
  uint64 len;
  if ( !PyW_GetNumber(py_len, &len) )
    Py_RETURN_NONE;
  if ( len == BADADDR )
    len = uint64(-1);
  qstring buf;
  if ( len != uint64(-1) && ea_t(ea + len) < ea
    || get_strlit_contents(&buf, ea, len, type, NULL, flags) < 0 )
  {
    Py_RETURN_NONE;
  }
  if ( type == STRTYPE_C && buf.length() > 0 && buf.last() == '\0' )
    buf.remove_last();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_buf(IDAPyStr_FromUTF8AndSize(buf.begin(), buf.length()));
  py_buf.incref();
  return py_buf.o;
}

//-------------------------------------------------------------------------
static ea_t py_bin_search(
        ea_t start_ea,
        ea_t end_ea,
        const uchar *image,
        size_t len,
        const uchar *mask,
        int step,
        int flags)
{
  if ( step != /* old value of BIN_SEARCH_FORWARD*/ 1
    && step != /* new value of BIN_SEARCH_FORWARD */ 0 )
  {
    flags |= BIN_SEARCH_BACKWARD;
  }
  bytevec_t lmask;
  if ( mask != NULL )
  {
    if ( *mask == 0xFF )
    {
      // a value of '0xFF' in the first byte meant "all bytes defined". We
      // can thus turn that into a NULL mask.
      mask = NULL;
    }
    else
    {
      // some bytes defined, some bytes aren't. Those that are have a value
      // 1 in the mask. We must turn them into 0xFF's
      lmask.resize(len);
      for ( size_t i = 0; i < len; ++i )
        lmask[i] = mask[i] != 0 ? 0xFF : 0;
      mask = lmask.begin();
    }
  }
  return bin_search2(start_ea, end_ea, image, mask, len, flags);
}

//-------------------------------------------------------------------------
static PyObject *py_print_strlit_type(int32 strtype, int flags=0)
{
  qstring s, t;
  if ( !print_strlit_type(&s, strtype, &t, flags) )
    Py_RETURN_NONE;
  return Py_BuildValue("(ss)", s.c_str(), t.c_str());
}

//-------------------------------------------------------------------------
static PyObject *py_get_octet(ea_t ea, uint64 v, int nbit)
{
  uchar octet = get_octet(&ea, &v, &nbit);
  return Py_BuildValue("(i" PY_BV_EA "Ki)", int(uint32(octet)), bvea_t(ea), v, nbit);
}

//-------------------------------------------------------------------------
static PyObject *py_get_8bit(ea_t ea, uint32 v, int nbit)
{
  uchar octet = get_8bit(&ea, &v, &nbit);
  return Py_BuildValue("(i" PY_BV_EA "ki)", int(uint32(octet)), bvea_t(ea), v, nbit);
}
//</inline(py_bytes)>

#endif
