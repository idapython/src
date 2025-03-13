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
static int py_visit_patched_bytes(ea_t ea1, ea_t ea2, PyObject *callable)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyCallable_Check(callable) )
    return 0;
  else
    return visit_patched_bytes(ea1, ea2, py_visit_patched_bytes_cb, callable);
}

//------------------------------------------------------------------------
static PyObject *py_get_bytes(ea_t ea, unsigned int size, int gmb_flags=GMB_READALL)
{
  PyObject *py_bytes = nullptr;
  if ( py_do_get_bytes(&py_bytes, nullptr, ea, size, gmb_flags) )
    return py_bytes;
  else
    Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
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
static PyObject *py_get_strlit_contents(
        ea_t ea,
        PyObject *len,
        int32 type,
        int flags = 0)
{
  uint64 llen;
  if ( !PyW_GetNumber(len, &llen) )
    Py_RETURN_NONE;
  if ( llen == BADADDR )
    llen = uint64(-1);
  qstring buf;
  if ( llen != uint64(-1) && ea_t(ea + llen) < ea
    || get_strlit_contents(&buf, ea, llen, type, nullptr, flags) < 0 )
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
static PyObject *py_print_strlit_type(int32 strtype, int flags=0)
{
  qstring s, t;
  if ( !print_strlit_type(&s, strtype, &t, flags) )
    Py_RETURN_NONE;
  return Py_BuildValue("(ss)", s.c_str(), t.c_str());
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
static int get_stroff_path(
        qvector<tid_t> *out_path,
        adiff_t *out_delta,
        ea_t ea,
        int n)
{
  if ( !is_stroff(get_flags(ea), n) )
    return -1;
  tid_t path[MAXSTRUCPATH];
  const int path_size = get_stroff_path(path, out_delta, ea, n);
  if ( path_size > 0 )
  {
    qvector<tid_t> storage;
    storage.reserve(path_size);
    for ( int i = 0; i < path_size; ++i )
      storage.push_back(path[i]);
    out_path->swap(storage);
  }
  return path_size;
}
//</inline(py_bytes)>

#endif
