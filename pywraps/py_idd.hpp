
//<code(py_idd)>
PyObject *py_appcall(
        ea_t func_ea,
        thid_t tid,
        const bytevec_t &_type_or_none,
        const bytevec_t &_fields,
        PyObject *arg_list)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( !PyList_Check(arg_list) )
    return nullptr;

  const type_t *type   = (const type_t *) _type_or_none.begin();
  const type_t *fields = (const p_list *) _fields.begin();
  tinfo_t tif;
  tinfo_t *ptif = nullptr;
  if ( tif.deserialize(nullptr, &type, &fields) )
    ptif = &tif;

  // Convert Python arguments into IDC values
  qvector<idc_value_t> idc_args;
  int sn = 0;
  Py_ssize_t nargs = PyList_Size(arg_list);
  idc_args.resize(nargs);
  bool ok = true;
  for ( Py_ssize_t i=0; i < nargs; i++ )
  {
    // Get argument
    borref_t py_item(PyList_GetItem(arg_list, i));
    if ( (debug & IDA_DEBUG_APPCALL) != 0 )
    {
      qstring s;
      PyW_ObjectToString(py_item.o, &s);
      msg("obj[%d]->%s\n", int(i), s.c_str());
    }
    // Convert it
    if ( pyvar_to_idcvar(py_item, &idc_args[i], &sn) < CIP_OK )
    {
      ok = false;
      break;
    }
  }

  // Set exception message
  if ( !ok )
  {
    PyErr_SetString(
        PyExc_ValueError,
        "PyAppCall: Failed to convert Python values to IDC values");
    return nullptr;
  }

  error_t ret;
  idc_value_t idc_result;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;

  if ( (debug & IDA_DEBUG_APPCALL) != 0 )
  {
    msg("input variables:\n"
        "----------------\n");

    qstring s;
    for ( Py_ssize_t i=0; i < nargs; i++ )
    {
      print_idcv(&s, idc_args[i]);
      msg("%d]\n%s\n-----------\n", int(i), s.c_str());
      s.qclear();
    }
  }

  // Do Appcall
  ret = dbg_appcall(&idc_result,
                    func_ea,
                    tid,
                    ptif,
                    idc_args.begin(),
                    idc_args.size());

  SWIG_PYTHON_THREAD_END_ALLOW;

  if ( ret != eOk )
  {
    // An exception was thrown?
    if ( ret == eExecThrow )
    {
      // Convert the result (which is a debug_event) into a Python object
      ref_t py_appcall_exc;
      idcvar_to_pyvar(idc_result, &py_appcall_exc);
      PyErr_SetObject(PyExc_OSError, py_appcall_exc.o);
      return nullptr;
    }
    // An error in the Appcall? (or an exception but AppCallOptions/DEBEV is not set)
    else
    {
      PyErr_SetString(PyExc_Exception, qstrerror(ret));
      return nullptr;
    }
  }

  if ( (debug & IDA_DEBUG_APPCALL) != 0 )
  {
    msg("return variables:\n"
        "-----------------\n");
    qstring s;
    for ( Py_ssize_t i=0; i < nargs; i++ )
    {
      print_idcv(&s, idc_args[i]);
      msg("%d]\n%s\n-----------\n", int(i), s.c_str());
      s.qclear();
    }
  }

  // Convert IDC values back to Python values
  for ( Py_ssize_t i=0; i < nargs; i++ )
  {
    // Get argument
    borref_t py_item(PyList_GetItem(arg_list, i));
    // We convert arguments but fail only on fatal errors
    // (we ignore failure because of immutable objects)
    if ( idcvar_to_pyvar(idc_args[i], &py_item) == CIP_FAILED )
    {
      PyErr_SetString(PyExc_ValueError, "PyAppCall: Failed while converting IDC values to Python values");
      return nullptr;
    }
  }

  // Convert the result from IDC back to Python
  // Any set of bytes (stored in a VT_STR), will have to be converted
  // to a 'bytes' object, not a string
  ref_t py_result;
  if ( idcvar_to_pyvar(idc_result, &py_result, PYWCVTF_STR_AS_BYTES) <= CIP_IMMUTABLE )
  {
    PyErr_SetString(PyExc_ValueError, "PyAppCall: Failed while converting IDC return value to Python return value");
    return nullptr;
  }
  if ( (debug & IDA_DEBUG_APPCALL) != 0 )
  {
    msg("return var:\n"
        "-----------\n");
    qstring s;
    print_idcv(&s, idc_result);
    msg("%s\n-----------\n", s.c_str());
  }
  py_result.incref();
  return py_result.o;
}
//</code(py_idd)>


//-------------------------------------------------------------------------
//<inline(py_idd)>

static debugger_t *get_dbg()
{
  return dbg;
}

/*
#<pydoc>
def dbg_get_registers():
    """
    This function returns the register definition from the currently loaded debugger.
    Basically, it returns an array of structure similar to to idd.hpp / register_info_t
    @return:
        None if no debugger is loaded
        tuple(name, flags, class, dtype, bit_strings, default_bit_strings_mask)
        The bit_strings can be a tuple of strings or None (if the register does not have bit_strings)
    """
    pass
#</pydoc>
*/
static PyObject *dbg_get_registers()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( dbg == nullptr )
    Py_RETURN_NONE;

  PyObject *py_list = PyList_New(dbg->nregs);

  for ( int i=0; i < dbg->nregs; i++ )
  {
    register_info_t &ri = dbg->regs(i);
    PyObject *py_bits;

    // Does this register have bit strings?
    // (Make sure it does not use custom formats because bit_string would be the format name)
    if ( ri.bit_strings != nullptr && (ri.flags & REGISTER_CUSTFMT) == 0 )
    {
      int nbits = (int)b2a_width((int)get_dtype_size(ri.dtype), 0) * 4;
      py_bits = PyList_New(nbits);
      for ( int i=0; i < nbits; i++ )
      {
        const char *s = ri.bit_strings[i];
        PyList_SetItem(py_bits, i, PyUnicode_FromString(s == nullptr ? "" : s));
      }
    }
    else
    {
      Py_INCREF(Py_None);
      py_bits = Py_None;
    }

    // name, flags, class, dtype, bit_strings, default_bit_strings_mask
    PyList_SetItem(py_list, i,
      Py_BuildValue("(sIIINI)",
        ri.name,
        ri.flags,
        (unsigned int)ri.register_class,
        (unsigned int)ri.dtype,
        py_bits,
        (unsigned int)ri.default_bit_strings_mask));
  }
  return py_list;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def dbg_get_thread_sreg_base(tid, sreg_value):
    """
    Returns the segment register base value
    @param tid: thread id
    @param sreg_value: segment register (selector) value
    @return:
        - The base as an 'ea'
        - Or None on failure
    """
    pass
#</pydoc>
*/
static PyObject *dbg_get_thread_sreg_base(thid_t tid, int sreg_value)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  ea_t answer;
  if ( !dbg_can_query(dbg) || internal_get_sreg_base(&answer, tid, sreg_value) != DRC_OK )
    Py_RETURN_NONE;
  return Py_BuildValue(PY_BV_EA, bvea_t(answer));
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def dbg_read_memory(ea, sz):
    """
    Reads from the debugee's memory at the specified ea
    @return:
        - The read buffer (as a string)
        - Or None on failure
    """
    pass
#</pydoc>
*/
static PyObject *dbg_read_memory(ea_t ea, size_t sz)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( !dbg_can_query(dbg) )
    Py_RETURN_NONE;

  // Create a Python string
  PyObject *ret = PyBytes_FromStringAndSize(nullptr, Py_ssize_t(sz));
  if ( ret == nullptr )
    Py_RETURN_NONE;

  // Get the internal buffer
  Py_ssize_t len;
  char *buf;
  PyBytes_AsStringAndSize(ret, &buf, &len);
  if ( size_t(read_dbg_memory(ea, buf, sz)) != sz )
  {
    Py_DECREF(ret);
    Py_RETURN_NONE;
  }
  return ret;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def dbg_write_memory(ea, buffer):
    """
    Writes a buffer to the debugee's memory
    @return: Boolean
    """
    pass
#</pydoc>
*/
static PyObject *dbg_write_memory(
        ea_t ea,
        const bytevec_t &buf)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( !dbg_can_query(dbg) )
    Py_RETURN_NONE;

  if ( write_dbg_memory(ea, buf.begin(), buf.size()) != buf.size() )
    Py_RETURN_FALSE;
  Py_RETURN_TRUE;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def dbg_get_name():
    """
    This function returns the current debugger's name.
    @return: Debugger name or None if no debugger is active
    """
    pass
#</pydoc>
*/
static PyObject *dbg_get_name()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( dbg == nullptr )
    Py_RETURN_NONE;
  else
    return PyUnicode_FromString(dbg->name);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def dbg_get_memory_info():
    """
    This function returns the memory configuration of a debugged process.
    @return:
        None if no debugger is active
        tuple(start_ea, end_ea, name, sclass, sbase, bitness, perm)
    """
    pass
#</pydoc>
*/
static PyObject *dbg_get_memory_info()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( !dbg_can_query(dbg) )
    Py_RETURN_NONE;

  // Invalidate memory
  meminfo_vec_t ranges;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  invalidate_dbgmem_config();
  invalidate_dbgmem_contents(BADADDR, BADADDR);

  get_dbg_memory_info(&ranges);
  SWIG_PYTHON_THREAD_END_ALLOW;
  return meminfo_vec_t_to_py(ranges);
}

//-------------------------------------------------------------------------
PyObject *py_appcall(
        ea_t func_ea,
        thid_t tid,
        const bytevec_t &_type_or_none,
        const bytevec_t &_fields,
        PyObject *arg_list);

char get_event_module_name(const debug_event_t *ev, char *buf, size_t bufsize)
{
  if ( ev == nullptr )
    return false;
  qstrncpy(buf, ev->modinfo().name.c_str(), bufsize);
  return true;
}

ea_t get_event_module_base(const debug_event_t *ev)
{
  return ev != nullptr ? ev->modinfo().base : BADADDR;
}

asize_t get_event_module_size(const debug_event_t *ev)
{
  return ev != nullptr ? ev->modinfo().size : 0;
}

char get_event_exc_info(const debug_event_t *ev, char *buf, size_t bufsize)
{
  if ( ev == nullptr )
    return false;
  qstrncpy(buf, ev->exc().info.c_str(), bufsize);
  return true;
}

char get_event_info(const debug_event_t *ev, char *buf, size_t bufsize)
{
  if ( ev == nullptr )
    return false;
  qstrncpy(buf, ev->info().c_str(), bufsize);
  return true;
}

ea_t get_event_bpt_hea(const debug_event_t *ev)
{
  return ev != nullptr ? ev->bpt().hea : BADADDR;
}

uint get_event_exc_code(const debug_event_t *ev)
{
  return ev != nullptr ? ev->exc().code : 0;
}

ea_t get_event_exc_ea(const debug_event_t *ev)
{
  return ev != nullptr ? ev->exc().ea : BADADDR;
}

bool can_exc_continue(const debug_event_t *ev)
{
  return ev != nullptr && ev->exc().can_cont;
}

//</inline(py_idd)>
