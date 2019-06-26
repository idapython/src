#ifndef __PYDBG__
#define __PYDBG__

//<code(py_dbg)>

// hookgenDBG:methodsinfo_def

//-------------------------------------------------------------------------
struct _cvt_status_t
{
  PyObject *def_err_class;
  const char *def_err_string;

  qstring err_string;
  PyObject *err_class;
  bool ok;

  _cvt_status_t(PyObject *_def_err_class, const char *_def_err_string)
    : def_err_class(_def_err_class),
    def_err_string(_def_err_string),
    err_class(NULL),
    ok(true) {}

  ~_cvt_status_t()
  {
    if ( !ok )
    {
      if ( err_class == NULL )
      {
        err_class = def_err_class;
        err_string = def_err_string;
      }
      PyErr_SetString(err_class, err_string.c_str());
    }
  }

  qstring &failed(PyObject *_err_class)
  {
    QASSERT(30587, ok == false);
    err_class = _err_class;
    return err_string;
  }
};


//-------------------------------------------------------------------------
static bool _to_reg_val(regval_t **out, regval_t *buf, const char *name, PyObject *o)
{
  if ( o == Py_None )
    return false;

  int cvt = SWIG_ConvertPtr(o, (void **) out, SWIGTYPE_p_regval_t, 0);
  if ( SWIG_IsOK(cvt) && *out != NULL )
    return true;

  register_info_t ri;
  if ( !get_dbg_reg_info(name, &ri) )
  {
    // we couldn't find the register information. This might
    // mean that we are accessing another, sub register (e.g.,
    // "eax" while the real register name is "rax".) Let's
    // assume the dtype is DWORD then
    ri.dtype = dt_dword;
  }

  struct ida_local cvt_t
  {
    static bool convert_int(regval_t *lout, PyObject *in, op_dtype_t dt)
    {
      uint64 u64 = 0;
      _cvt_status_t status(PyExc_TypeError, "Expected integer value");
      size_t nbits = 0;
      switch ( dt )
      {
        case dt_byte: nbits = 8; break;
        case dt_word: nbits = 16; break;
        default:
        case dt_dword: nbits = 32; break;
        case dt_qword: nbits = 64; break;
      }
      status.ok = PyW_GetNumber(in, &u64);
      if ( status.ok )
      {
        if ( nbits < 64 )
        {
          status.ok = u64 < (1ULL << nbits);
          if ( !status.ok )
            status.failed(PyExc_ValueError).sprnt("Integer value too large to fit in %" FMT_Z " bits", nbits);
        }
      }
      if ( status.ok )
        lout->set_int(u64);
      return status.ok;
    }

    static bool convert_float(regval_t *lout, PyObject *in, op_dtype_t)
    {
      eNE ene;
      _cvt_status_t status(PyExc_TypeError, "Expected float value");
      double dbl = PyFloat_AsDouble(in);
      status.ok = PyErr_Occurred() == NULL;
      if ( status.ok )
        status.ok = ieee_realcvt(&dbl, ene, 003 /*load double*/) == 0;
      if ( !status.ok )
        status.failed(PyExc_ValueError).sprnt("Float conversion failed");
      if ( status.ok )
        lout->set_float(ene);
      return status.ok;
    }

    static bool convert_bytes(regval_t *lout, PyObject *in, op_dtype_t dt)
    {
      bytevec_t bytes;
      _cvt_status_t status(PyExc_TypeError, "Unexpected value");
      size_t nbytes = 0;
      switch ( dt )
      {
        case dt_byte16: nbytes = 16; break;
        case dt_byte32: nbytes = 32; break;
        case dt_byte64: nbytes = 64; break;
        default:
          break;
      }
      status.ok = nbytes > 0;
      Py_ssize_t got;
      if ( status.ok )
      {
        status.ok = false;
        if ( PyString_Check(in) )
        {
          char *buf;
          status.ok = PyString_AsStringAndSize(in, &buf, &got) >= 0 && got <= nbytes;
          if ( status.ok )
            bytes.append((const uchar *) buf, got);
          else
            status.failed(PyExc_ValueError).sprnt(
                    "List of bytes is too long; was expecting at most %d bytes",
                    int(nbytes));
        }
        else if ( PyInt_Check(in) )
        {
          uint64 u64 = 0;
          status.ok = PyW_GetNumber(in, &u64);
          if ( status.ok )
          {
            got = sizeof(u64);
            bytes.resize(got, 0);
            memcpy(bytes.begin(), &u64, got);
          }
        }
        else if ( PyLong_CheckExact(in) )
        {
          // (possibly very long) int or long value. Apparently it's rather
          // safe to use _PyLong_AsByteArray (it's even present in 3.x)
          // https://stackoverflow.com/questions/18290507/python-extension-construct-and-inspect-large-integers-efficiently

          // /* _PyLong_AsByteArray: Convert the least-significant 8*n bits of long
          //    v to a base-256 integer, stored in array bytes.  Normally return 0,
          //    return -1 on error.
          //    If little_endian is 1/true, store the MSB at bytes[n-1] and the LSB at
          //    bytes[0]; else (little_endian is 0/false) store the MSB at bytes[0] and
          //    the LSB at bytes[n-1].
          //    If is_signed is 0/false, it's an error if v < 0; else (v >= 0) n bytes
          //    are filled and there's nothing special about bit 0x80 of the MSB.
          //    If is_signed is 1/true, bytes is filled with the 2's-complement
          //    representation of v's value.  Bit 0x80 of the MSB is the sign bit.
          //    Error returns (-1):
          //    + is_signed is 0 and v < 0.  TypeError is set in this case, and bytes
          //      isn't altered.
          //    + n isn't big enough to hold the full mathematical value of v.  For
          //      example, if is_signed is 0 and there are more digits in the v than
          //      fit in n; or if is_signed is 1, v < 0, and n is just 1 bit shy of
          //      being large enough to hold a sign bit.  OverflowError is set in this
          //      case, but bytes holds the least-significant n bytes of the true value.
          // */
          bytes.resize(nbytes, 0);
          status.ok = _PyLong_AsByteArray(
                  (PyLongObject *) in,
                  bytes.begin(),
                  bytes.size(),
                  /*little_endian=*/ 1,
                  /*is_signed=*/ 1) >= 0;
          if ( status.ok )
            got = nbytes;
          else
            status.failed(PyExc_ValueError).sprnt(
                    "Integer value is too large to fit in %d bytes",
                    int(nbytes));
        }
      }
      if ( status.ok )
      {
        bytes.growfill(nbytes - got, 0);
        lout->set_bytes(bytes);
      }
      return status.ok;
    }
  };

  bool ok = false;
  regval_t &rv = *buf;
  switch ( ri.dtype )
  {
    case dt_byte:
    case dt_word:
    case dt_dword:
    case dt_qword:
    default:
      ok = cvt_t::convert_int(&rv, o, ri.dtype);
      break;
    case dt_float:
    case dt_tbyte:
    case dt_double:
    case dt_ldbl:
      ok = cvt_t::convert_float(&rv, o, ri.dtype);
      break;
    case dt_byte16:
    case dt_byte32:
    case dt_byte64:
      ok = cvt_t::convert_bytes(&rv, o, ri.dtype);
      break;
  }
  if ( ok )
    *out = &rv;
  return ok;
}

//-------------------------------------------------------------------------
static PyObject *_from_reg_val(
        const char *name,
        const regval_t &rv)
{
  register_info_t ri;
  if ( !get_dbg_reg_info(name, &ri) ) // see _to_reg_val()
    ri.dtype = dt_dword;

  PyObject *res = NULL;
  _cvt_status_t status(PyExc_ValueError, "Conversion failed");
  switch ( ri.dtype )
  {
    default:
      if ( rv.ival <= uint64(PyInt_GetMax()) )
        res = PyInt_FromLong(long(rv.ival));
      else
        res = PyLong_FromUnsignedLongLong((unsigned PY_LONG_LONG) rv.ival);
      break;
    case dt_float:
    case dt_tbyte:
    case dt_double:
    case dt_ldbl:
      {
        double dbl;
        status.ok = ieee_realcvt(&dbl, (uint16 *) rv.fval, 013 /*store double*/) == 0;
        if ( status.ok )
          res = PyFloat_FromDouble(dbl);
      }
      break;
    case dt_byte16:
    case dt_byte32:
    case dt_byte64:
      {
        const bytevec_t &b = rv.bytes();
        res = PyString_FromStringAndSize((const char *) b.begin(), b.size());
      }
      break;
  }
  return res;
}
//</code(py_dbg)>

//<inline(py_dbg)>

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_manual_regions():
    """
    Returns the manual memory regions
    @return: list(start_ea, end_ea, name, sclass, sbase, bitness, perm)
    """
    pass
#</pydoc>
*/
static PyObject *py_get_manual_regions()
{
  meminfo_vec_t ranges;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  get_manual_regions(&ranges);
  SWIG_PYTHON_THREAD_END_ALLOW;
  return meminfo_vec_t_to_py(ranges);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def dbg_is_loaded():
    """
    Checks if a debugger is loaded
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool dbg_is_loaded()
{
  return dbg != NULL;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def refresh_debugger_memory():
    """
    Refreshes the debugger memory
    @return: Nothing
    """
    pass
#</pydoc>
*/
static PyObject *refresh_debugger_memory()
{
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  invalidate_dbgmem_config();
  invalidate_dbgmem_contents(BADADDR, 0);

  // Ask the debugger to populate debug names
  if ( dbg != NULL )
    dbg->suspended(true);

  // Invalidate the cache
  is_mapped(0);
  SWIG_PYTHON_THREAD_END_ALLOW;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  Py_RETURN_NONE;
}

ssize_t idaapi DBG_Callback(void *ud, int notification_code, va_list va);
struct DBG_Hooks : public hooks_base_t
{
  // hookgenDBG:methodsinfo_decl

  DBG_Hooks(uint32 _flags=0)
    : hooks_base_t("ida_dbg.DBG_Hooks", DBG_Callback, HT_DBG, _flags) {}

  bool hook() { return hooks_base_t::hook(); }
  bool unhook() { return hooks_base_t::unhook(); }
#ifdef TESTABLE_BUILD
  qstring dump_state() { return hooks_base_t::dump_state(mappings, mappings_size); }
#endif

  // hookgenDBG:methods

  ssize_t dispatch(int code, va_list va)
  {
    ssize_t ret = 0;
    switch ( code )
    {
      // hookgenDBG:notifications
    }
    return ret;
  }

private:
  static ssize_t store_int(int rc, const debug_event_t *, int *warn)
  {
    *warn = rc;
    return 0;
  }

  static ssize_t store_int(int rc, thid_t, ea_t, int *warn)
  {
    *warn = rc;
    return 0;
  }
};

//-------------------------------------------------------------------------
ssize_t idaapi DBG_Callback(void *ud, int code, va_list va)
{
  // hookgenDBG:safecall=DBG_Hooks
}


//------------------------------------------------------------------------
/*
#<pydoc>
def py_list_bptgrps():
    """
    Returns list of breakpoint group names
    @return: A list of strings or None on failure
    """
    pass
#</pydoc>
*/
static PyObject *py_list_bptgrps()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  qstrvec_t args;
  if ( list_bptgrps(&args) == 0 )
    Py_RETURN_NONE;
  return qstrvec2pylist(args);
}

//------------------------------------------------------------------------
/*
#<pydoc>
def move_bpt_to_grp():
    """
    Sets new group for the breakpoint
    """
    pass
#</pydoc>
*/
static void move_bpt_to_grp(bpt_t *bpt, const char *grp_name)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  set_bpt_group(*bpt, grp_name);
}

/*
#<pydoc>
def internal_get_sreg_base():
    """
    Get the sreg base, for the given thread.

    @return: The sreg base, or BADADDR on failure.
    """
    pass
#</pydoc>
*/
static ea_t py_internal_get_sreg_base(thid_t tid, int sreg_value)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ea_t answer;
  return internal_get_sreg_base(&answer, tid, sreg_value) <= DRC_NONE
       ? BADADDR
       : answer;
}

//-------------------------------------------------------------------------
static ssize_t py_write_dbg_memory(ea_t ea, PyObject *py_buf, size_t size=size_t(-1))
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !dbg_can_query() || !PyString_Check(py_buf) )
    return -1;
  char *buf = NULL;
  Py_ssize_t sz;
  if ( PyString_AsStringAndSize(py_buf, &buf, &sz) < 0 )
    return -1;
  if ( size == size_t(-1) )
    size = size_t(sz);
  return write_dbg_memory(ea, buf, size);
}

/*
#<pydoc>
def dbg_can_query():
    """
    This function can be used to check if the debugger can be queried:
      - debugger is loaded
      - process is suspended
      - process is not suspended but can take requests. In this case some requests like
        memory read/write, bpt management succeed and register querying will fail.
        Check if idaapi.get_process_state() < 0 to tell if the process is suspended
    @return: Boolean
    """
    pass
#</pydoc>
*/

//-------------------------------------------------------------------------
static PyObject *py_set_reg_val(const char *regname, PyObject *o)
{
  regval_t buf;
  regval_t *ptr;
  if ( !_to_reg_val(&ptr, &buf, regname, o) )
    return NULL;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  bool ok = set_reg_val(regname, ptr);
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( !ok )
  {
    PyErr_SetString(PyExc_Exception, "Failed to set register value");
    Py_RETURN_FALSE;
  }
  Py_RETURN_TRUE;
}

//-------------------------------------------------------------------------
static PyObject *py_set_reg_val(thid_t tid, int regidx, PyObject *o)
{
  if ( dbg == NULL )
  {
    PyErr_SetString(PyExc_Exception, "No debugger loaded");
    return NULL;
  }
  if ( regidx < 0 || regidx >= dbg->nregs )
  {
    qstring buf;
    buf.sprnt("Bad register index: %d", regidx);
    PyErr_SetString(PyExc_Exception, buf.c_str());
    return NULL;
  }
  const register_info_t &ri = dbg->regs(regidx);
  regval_t buf;
  regval_t *ptr;
  if ( !_to_reg_val(&ptr, &buf, ri.name, o) )
    return NULL;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  bool ok = set_reg_val(tid, regidx, ptr);
  SWIG_PYTHON_THREAD_END_ALLOW;
  return PyInt_FromLong(ok);
}

//-------------------------------------------------------------------------
static PyObject *py_request_set_reg_val(const char *regname, PyObject *o)
{
  regval_t buf;
  regval_t *ptr;
  if ( !_to_reg_val(&ptr, &buf, regname, o) )
    return NULL;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  bool ok = request_set_reg_val(regname, ptr);
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( !ok )
  {
    PyErr_SetString(PyExc_Exception, "Failed to request set register value");
    Py_RETURN_FALSE;
  }
  Py_RETURN_TRUE;
}

//-------------------------------------------------------------------------
static PyObject *py_get_reg_val(const char *regname)
{
  regval_t buf;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  bool ok = get_reg_val(regname, &buf);
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( !ok )
  {
    PyErr_SetString(PyExc_Exception, "Failed to retrieve register value");
    return NULL;
  }
  return _from_reg_val(regname, buf);
}

//</inline(py_dbg)>
#endif
