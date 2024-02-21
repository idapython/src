#ifndef __PY_IDA_BYTES__
#define __PY_IDA_BYTES__

//<code(py_bytes)>

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
  return (py_result && PyLong_Check(py_result.o)) ? PyLong_AsLong(py_result.o) : 0;
}

//-------------------------------------------------------------------------
static void ida_bytes_init(void) {}
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
  bool has_mask = out_py_mask != nullptr;
  do
  {
    if ( size <= 0 )
      break;

    // Allocate memory via Python

    newref_t py_bytes(PyBytes_FromStringAndSize(nullptr, Py_ssize_t(size)));
    if ( !py_bytes )
      break;

    bytevec_t mask;
    if ( has_mask )
      mask.resize((size + 7) / 8, 0);

    // Read bytes
    int code = get_bytes(PyBytes_AsString(py_bytes.o),
                         size,
                         ea,
                         gmb_flags,
                         has_mask ? mask.begin() : nullptr);
    if ( code < 0 )
      break;

    // note: specify size, as '0' bytes would otherwise cut the mask short
    if ( has_mask )
    {
      newref_t py_mask(PyBytes_FromStringAndSize(
                               (const char *) mask.begin(),
                               mask.size()));
      if ( !py_mask )
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

#define MS_0TYPE 0x00F00000 ///< Mask for 1st arg typing
#define FF_0VOID 0x00000000 ///< Void (unknown)?
#define FF_0NUMH 0x00100000 ///< Hexadecimal number?
#define FF_0NUMD 0x00200000 ///< Decimal number?
#define FF_0CHAR 0x00300000 ///< Char ('x')?
#define FF_0SEG  0x00400000 ///< Segment?
#define FF_0OFF  0x00500000 ///< Offset?
#define FF_0NUMB 0x00600000 ///< Binary number?
#define FF_0NUMO 0x00700000 ///< Octal number?
#define FF_0ENUM 0x00800000 ///< Enumeration?
#define FF_0FOP  0x00900000 ///< Forced operand?
#define FF_0STRO 0x00A00000 ///< Struct offset?
#define FF_0STK  0x00B00000 ///< Stack variable?
#define FF_0FLT  0x00C00000 ///< Floating point number?
#define FF_0CUST 0x00D00000 ///< Custom representation?

#define MS_1TYPE 0x0F000000 ///< Mask for the type of other operands
#define FF_1VOID 0x00000000 ///< Void (unknown)?
#define FF_1NUMH 0x01000000 ///< Hexadecimal number?
#define FF_1NUMD 0x02000000 ///< Decimal number?
#define FF_1CHAR 0x03000000 ///< Char ('x')?
#define FF_1SEG  0x04000000 ///< Segment?
#define FF_1OFF  0x05000000 ///< Offset?
#define FF_1NUMB 0x06000000 ///< Binary number?
#define FF_1NUMO 0x07000000 ///< Octal number?
#define FF_1ENUM 0x08000000 ///< Enumeration?
#define FF_1FOP  0x09000000 ///< Forced operand?
#define FF_1STRO 0x0A000000 ///< Struct offset?
#define FF_1STK  0x0B000000 ///< Stack variable?
#define FF_1FLT  0x0C000000 ///< Floating point number?
#define FF_1CUST 0x0D000000 ///< Custom representation?

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
  PyObject *py_bytes = nullptr;
  if ( py_do_get_bytes(&py_bytes, nullptr, ea, size, gmb_flags) )
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
  PyObject *py_bytes = nullptr;
  PyObject *py_mask = nullptr;
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
  Get contents of string literal, as UTF-8-encoded codepoints.
  It works even if the string has not been created in the database yet.

  Note that the returned value will be of type 'bytes'; if
  you want auto-conversion to unicode strings (that is: real Python
  strings), you should probably be using the idautils.Strings class.

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
    || get_strlit_contents(&buf, ea, len, type, nullptr, flags) < 0 )
  {
    Py_RETURN_NONE;
  }
  if ( type == STRTYPE_C && buf.length() > 0 && buf.last() == '\0' )
    buf.remove_last();
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t py_buf(PyBytes_FromStringAndSize(buf.begin(), buf.length()));
  py_buf.incref();
  return py_buf.o;
}

//-------------------------------------------------------------------------
static ea_t py_bin_search(
        ea_t start_ea,
        ea_t end_ea,
        const bytevec_t &image,
        const bytevec_t &imask,
        int step,
        int flags)
{
  if ( image.empty() )
    return BADADDR;
  if ( step != /* old value of BIN_SEARCH_FORWARD*/ 1
    && step != /* new value of BIN_SEARCH_FORWARD */ 0 )
  {
    flags |= BIN_SEARCH_BACKWARD;
  }
  const size_t len = image.size();
  const uchar *mask = imask.begin();
  bytevec_t lmask;
  if ( mask != nullptr )
  {
    if ( *mask == 0xFF )
    {
      // a value of '0xFF' in the first byte meant "all bytes defined". We
      // can thus turn that into a nullptr mask.
      mask = nullptr;
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
  return bin_search2(start_ea, end_ea, image.begin(), mask, len, flags);
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

//-------------------------------------------------------------------------
static bool ida_export py_op_stroff(
        const insn_t &insn,
        int n,
        const qvector<tid_t> &path,
        adiff_t delta)
{
  return op_stroff(insn, n, path.begin(), path.size(), delta);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def bin_search(start_ea, end_ea, data, flags):
  """
  Search for a set of bytes in the program

  @param start_ea: linear address, start of range to search
  @param end_ea: linear address, end of range to search (exclusive)
  @param data: the prepared data to search for (see parse_binpat_str())
  @param flags: combination of BIN_SEARCH_* flags
  @return: the address of a match, or ida_idaapi.BADADDR if not found
  """
  pass
#</pydoc>
*/

//</inline(py_bytes)>

#endif
