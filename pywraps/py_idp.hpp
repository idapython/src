#ifndef __PY_IDP__
#define __PY_IDP__

//-------------------------------------------------------------------------
//<inline(py_idp)>
//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
/*
#<pydoc>
def AssembleLine(ea, cs, ip, use32, line):
    """
    Assemble an instruction to a string (display a warning if an error is found)

    @param ea: linear address of instruction
    @param cs:  cs of instruction
    @param ip:  ip of instruction
    @param use32: is 32bit segment
    @param line: line to assemble
    @return:
        - None on failure
        - or a string containing the assembled instruction
    """
    pass
#</pydoc>
*/
static PyObject *AssembleLine(
        ea_t ea,
        ea_t cs,
        ea_t ip,
        bool use32,
        const char *line)
{
  char buf[MAXSTR];
  int inslen = processor_t::assemble((uchar *)buf, ea, cs, ip, use32, line);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( inslen > 0 )
    return PyBytes_FromStringAndSize(buf, inslen);
  else
    Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
/*
#<pydoc>
def assemble(ea, cs, ip, use32, line):
    """
    Assemble an instruction into the database (display a warning if an error is found)
    @param ea: linear address of instruction
    @param cs: cs of instruction
    @param ip: ip of instruction
    @param use32: is 32bit segment?
    @param line: line to assemble

    @return: Boolean. True on success.
    """
#</pydoc>
*/
bool assemble(
        ea_t ea,
        ea_t cs,
        ea_t ip,
        bool use32,
        const char *line)
{
  char buf[MAXSTR];
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc = false;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  int inslen = processor_t::assemble((uchar *)buf, ea, cs, ip, use32, line);
  if ( inslen > 0 )
  {
    patch_bytes(ea, buf, inslen);
    rc = true;
  }
  SWIG_PYTHON_THREAD_END_ALLOW;
  return rc;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_id():
    """
    Returns the 'ph.id' field
    """
    pass
#</pydoc>
*/
static size_t ph_get_id()
{
  return PH.id;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_version():
    """
    Returns the 'ph.version'
    """
    pass
#</pydoc>
*/
static size_t ph_get_version()
{
  return PH.version;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_flag():
    """
    Returns the 'ph.flag'
    """
    pass
#</pydoc>
*/
static size_t ph_get_flag()
{
  return PH.flag;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_cnbits():
    """
    Returns the 'ph.cnbits'
    """
    pass
#</pydoc>
*/
static size_t ph_get_cnbits()
{
  return PH.cnbits;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_dnbits():
    """
    Returns the 'ph.dnbits'
    """
    pass
#</pydoc>
*/
static size_t ph_get_dnbits()
{
  return PH.dnbits;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_reg_first_sreg():
    """
    Returns the 'ph.reg_first_sreg'
    """
    pass
#</pydoc>
*/
static size_t ph_get_reg_first_sreg()
{
  return PH.reg_first_sreg;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_reg_last_sreg():
    """
    Returns the 'ph.reg_last_sreg'
    """
    pass
#</pydoc>
*/
static size_t ph_get_reg_last_sreg()
{
  return PH.reg_last_sreg;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_segreg_size():
    """
    Returns the 'ph.segreg_size'
    """
    pass
#</pydoc>
*/
static size_t ph_get_segreg_size()
{
  return PH.segreg_size;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_reg_code_sreg():
    """
    Returns the 'ph.reg_code_sreg'
    """
    pass
#</pydoc>
*/
static size_t ph_get_reg_code_sreg()
{
  return PH.reg_code_sreg;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_reg_data_sreg():
    """
    Returns the 'ph.reg_data_sreg'
    """
    pass
#</pydoc>
*/
static size_t ph_get_reg_data_sreg()
{
  return PH.reg_data_sreg;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_icode_return():
    """
    Returns the 'ph.icode_return'
    """
    pass
#</pydoc>
*/
static size_t ph_get_icode_return()
{
  return PH.icode_return;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_instruc_start():
    """
    Returns the 'ph.instruc_start'
    """
    pass
#</pydoc>
*/
static size_t ph_get_instruc_start()
{
  return PH.instruc_start;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_instruc_end():
    """
    Returns the 'ph.instruc_end'
    """
    pass
#</pydoc>
*/
static size_t ph_get_instruc_end()
{
  return PH.instruc_end;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_tbyte_size():
    """
    Returns the 'ph.tbyte_size' field as defined in he processor module
    """
    pass
#</pydoc>
*/
static size_t ph_get_tbyte_size()
{
  return PH.tbyte_size;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_instruc():
    """
    Returns a list of tuples (instruction_name, instruction_feature) containing the
    instructions list as defined in he processor module
    """
    pass
#</pydoc>
*/
static PyObject *ph_get_instruc()
{
  Py_ssize_t i = 0;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  processor_t &ph = PH;
  PyObject *py_result = PyList_New(ph.instruc_end - ph.instruc_start);
  for ( const instruc_t *p = ph.instruc + ph.instruc_start, *end = ph.instruc + ph.instruc_end;
        p != end;
        ++p )
  {
    PyList_SetItem(py_result, i++, Py_BuildValue("(sI)", p->name, p->feature));
  }
  return py_result;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_regnames():
    """
    Returns the list of register names as defined in the processor module
    """
    pass
#</pydoc>
*/
static PyObject *ph_get_regnames()
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  processor_t &ph = PH;
  PyObject *py_result = PyList_New(ph.regs_num);
  for ( Py_ssize_t i=0; i < ph.regs_num; i++ )
    PyList_SetItem(py_result, i, PyUnicode_FromString(ph.reg_names[i]));
  return py_result;
}

//---------------------------------------------------------------------------
static const regval_t *idaapi _py_getreg(
        const char *name,
        const regval_t *regvals);

/*
#<pydoc>
def ph_get_operand_info():
    """
    Returns the operand information given an ea and operand number.

    @param ea: address
    @param n: operand number

    @return: Returns an idd_opinfo_t as a tuple: (modified, ea, reg_ival, regidx, value_size).
             Please refer to idd_opinfo_t structure in the SDK.
    """
    pass
#</pydoc>
*/
static PyObject *ph_get_operand_info(
        ea_t ea,
        int n)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool ok = false;
  idd_opinfo_t opinf;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  do
  {
    if ( dbg == nullptr || n == - 1 )
      break;

    // Allocate register space
    thid_t tid = get_current_thread();
    regvals_t regvalues;
    regvalues.resize(dbg->nregs);
    // Read registers
    if ( get_reg_vals(tid, -1, regvalues.begin()) != DRC_OK )
      break;

    // Call the processor module
    if ( processor_t::notify(processor_t::ev_get_idd_opinfo,
                             &opinf,
                             ea,
                             n,
                             tid,
                             _py_getreg,
                             regvalues.begin()) == 0 )
    {
      break;
    }
    ok = true;
  } while (false);

  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( ok )
    return Py_BuildValue("(i" PY_BV_EA "Kii)",
                         opinf.modified,
                         bvea_t(opinf.ea),
                         opinf.value.ival,
                         opinf.debregidx,
                         opinf.value_size);
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
static void ph_calcrel(bytevec_t *out_relbits, size_t *out_consumed, ea_t ea)
{
  processor_t::calcrel(out_relbits, out_consumed, ea);
}

//-------------------------------------------------------------------------
static ssize_t ph_find_reg_value(uval_t *out, const insn_t &insn, int reg)
{
  return processor_t::find_reg_value(out, insn, reg);
}

//-------------------------------------------------------------------------
static ssize_t ph_find_op_value(uval_t *out, const insn_t &insn, int op)
{
  return processor_t::find_op_value(out, insn, op);
}

//-------------------------------------------------------------------------
static ssize_t ph_get_reg_accesses(
        reg_accesses_t *accvec,
        const insn_t &insn,
        int flags)
{
  return processor_t::get_reg_accesses(accvec, insn, flags);
}

//---------------------------------------------------------------------------
// IDP hooks
//---------------------------------------------------------------------------

// Necessary forward declarations; idp.hpp itself doesn't need them.
struct mblock_t;
struct proc_def;
struct libfunc_t;

ssize_t idaapi IDP_Callback(void *ud, int notification_code, va_list va);
struct IDP_Hooks : public hooks_base_t
{
  // hookgenIDP:methodsinfo_decl

  IDP_Hooks(uint32 _flags=0, uint32 _hkcb_flags=HKCB_GLOBAL)
    : hooks_base_t("ida_idp.IDP_Hooks", IDP_Callback, HT_IDP, _flags, _hkcb_flags) {}

  bool hook() { return hooks_base_t::hook(); }
  bool unhook() { return hooks_base_t::unhook(); }
#ifdef TESTABLE_BUILD
  PyObject *dump_state(bool assert_all_reimplemented=false) { return hooks_base_t::dump_state(mappings, mappings_size, assert_all_reimplemented); }
#endif

  // hookgenIDP:methods

  ssize_t dispatch(int code, va_list va)
  {
    ssize_t ret = 0;
    switch ( code )
    {
      // hookgenIDP:notifications
    }
    return ret;
  }

protected:
  static PyObject *new_PyObject_from_idpopt_value(
        int value_type,
        const void *value)
  {
    switch ( value_type )
    {
      case IDPOPT_STR:
        return PyUnicode_FromString((const char *) value);
      case IDPOPT_NUM:
#ifdef __EA64__
        return PyLong_FromLongLong(*(const uval_t *) value);
#else
        return PyLong_FromLong(*(const uval_t *) value);
#endif
      case IDPOPT_BIT:
        return PyLong_FromLong(*(const int *) value);
      case IDPOPT_I64:
        return PyLong_FromLongLong(*(const int64 *) value);
      default:
        return nullptr;
    }
  }

private:
  static ssize_t bool_to_insn_t_size(bool in, const insn_t *insn) { return in ? insn->size : 0; }
  static ssize_t bool_to_1or0(bool in) { return in ? 1 : 0; }
  static ssize_t cm_t_to_ssize_t(cm_t cm) { return ssize_t(cm); }
  static bool _handle_qstring_output(PyObject *o, qstring *buf)
  {
    bool is_str = o != nullptr && PyUnicode_Check(o);
    if ( is_str && buf != nullptr )
      PyUnicode_as_qstring(buf, o);
    Py_XDECREF(o);
    return is_str;
  }
  static ssize_t handle_custom_mnem_output(PyObject *o, qstring *out, const insn_t *)
  {
    return _handle_qstring_output(o, out) && !out->empty() ? 1 : 0;
  }
  static ssize_t handle_assemble_output(
        PyObject *o,
        uchar *bin,
        ea_t /*ea*/,
        ea_t /*cs*/,
        ea_t /*ip*/,
        bool /*use32*/,
        const char * /*line*/)
  {
    ssize_t rc = 0;
    if ( o != nullptr && PyBytes_Check(o) )
    {
      char *s;
      Py_ssize_t len = 0;
      if ( PyBytes_AsStringAndSize(o, &s, &len) != -1 )
      {
        if ( len > MAXSTR )
          len = MAXSTR;
        memcpy(bin, s, len);
      }
      rc = ssize_t(len);
    }
    Py_XDECREF(o);
    return rc;
  }
  static ssize_t handle_get_reg_name_output(PyObject *o, qstring *buf, int /*reg*/, size_t /*width*/, int /*reghi*/)
  {
    return _handle_qstring_output(o, buf) ? buf->length() : 0;
  }
  static ssize_t handle_decorate_name3_output(PyObject *o, qstring *outbuf, const char * /*name*/, bool /*mangle*/, int /*cc*/, const tinfo_t * /*type*/)
  {
    return _handle_qstring_output(o, outbuf) ? 1 : 0;
  }
  static ssize_t handle_delay_slot_insn_output(PyObject *o, ea_t *pea, bool *pbexec, bool *pfexec)
  {
    if ( PySequence_Check(o) && PySequence_Size(o) == 3 )
    {
      newref_t py_ea(PySequence_GetItem(o, 0));
      newref_t py_bexec(PySequence_GetItem(o, 1));
      newref_t py_fexec(PySequence_GetItem(o, 2));
      uint64 nea = 0;
      if ( PyW_GetNumber(py_ea.o, &nea)
        && PyBool_Check(py_bexec.o)
        && PyBool_Check(py_fexec.o) )
      {
        if ( pea != nullptr )
          *pea = nea;
        if ( pbexec != nullptr )
          *pbexec = py_bexec.o == Py_True;
        if ( pfexec != nullptr )
          *pfexec = py_fexec.o == Py_True;
        return 1;
      }
    }
    return -1;
  }
  static ssize_t handle_use_regarg_type_output(PyObject *o, int *idx, ea_t, const funcargvec_t *)
  {
    ssize_t rc = 0;
    if ( PySequence_Check(o) && PySequence_Size(o) == 2 )
    {
      newref_t py_rc(PySequence_GetItem(o, 0));
      newref_t py_idx(PySequence_GetItem(o, 1));
      if ( PyLong_Check(py_rc.o) && PyLong_Check(py_idx.o) )
      {
        rc = PyLong_AsLong(py_rc.o);
        *idx = PyLong_AsLong(py_idx.o);
      }
    }
    return rc;
  }
  static ssize_t handle_demangle_name_output(
        PyObject *o,
        int32 *out_res,
        qstring *out,
        const char * /*name*/,
        uint32 /*disable_mask*/,
        demreq_type_t /*demreq*/)
  {
    ssize_t rc = 0;
    if ( PySequence_Check(o) && PySequence_Size(o) == 3 )
    {
      newref_t py_rc(PySequence_GetItem(o, 0));
      newref_t py_out(PySequence_GetItem(o, 1));
      newref_t py_out_res(PySequence_GetItem(o, 2));
      qstring qs;
      if ( PyLong_Check(py_rc.o)
        && PyLong_Check(py_out_res.o)
        && PyUnicode_Check(py_out.o)
        && PyUnicode_as_qstring(&qs, py_out.o) )
      {
        rc = PyLong_AsLong(py_rc.o);
        *out_res = PyLong_AsLong(py_out_res.o);
        if ( out != nullptr )
          out->swap(qs);
      }
    }
    return rc;
  }
  static ssize_t handle_find_value_output(
        PyObject *o,
        uval_t *out,
        const insn_t * /*pinsn*/,
        int /*reg*/)
  {
    uint64 num;
    ssize_t rc = PyW_GetNumber(o, &num);
    if ( rc )
      *out = num;
    return rc;
  }
  static ssize_t handle_get_autocmt_output(
        PyObject *o,
        qstring *buf,
        const insn_t * /*pinsn*/)
  {
    return PyUnicode_Check(o) && PyUnicode_as_qstring(buf, o);
  }
  static ssize_t handle_get_operand_string_output(
        PyObject *o,
        qstring *buf,
        const insn_t * /*pinsn*/,
        int /*opnum*/)
  {
    return PyUnicode_Check(o) && PyUnicode_as_qstring(buf, o);
  }
};

//-------------------------------------------------------------------------
static PyObject *_wrap_addr_in_pycapsule(void *addr);
PyObject *get_idp_notifier_addr(PyObject *)
{
  return _wrap_addr_in_pycapsule((void *) IDP_Callback);
}

//-------------------------------------------------------------------------
PyObject *get_idp_notifier_ud_addr(IDP_Hooks *hooks)
{
  return _wrap_addr_in_pycapsule(hooks);
}

//-------------------------------------------------------------------------
inline bool delay_slot_insn(ea_t *ea, bool *bexec, bool *fexec)
{
  processor_t &ph = PH;
  return ph.delay_slot_insn(ea, bexec, fexec);
}

//-------------------------------------------------------------------------
inline const char *get_reg_info(const char *regname, bitrange_t *bitrange)
{
  processor_t &ph = PH;
  return ph.get_reg_info(regname, bitrange);
}

//-------------------------------------------------------------------------
inline size_t sizeof_ldbl(void)
{
  processor_t &ph = PH;
  return ph.sizeof_ldbl();
}
//</inline(py_idp)>

//-------------------------------------------------------------------------
//<code(py_idp)>

// hookgenIDP:methodsinfo_def

//-------------------------------------------------------------------------
static PyObject *_wrap_addr_in_pycapsule(void *addr)
{
  return PyCapsule_New(addr, VALID_CAPSULE_NAME, nullptr);
}

//-------------------------------------------------------------------------
ssize_t idaapi IDP_Callback(void *ud, int code, va_list va)
{
  // hookgenIDP:safecall=IDP_Hooks
}

//-------------------------------------------------------------------------
static const regval_t *idaapi _py_getreg(
        const char *name,
        const regval_t *regvals)
{
  for ( int i=dbg->nregs - 1; i >= 0; i-- )
  {
    if ( strieq(name, dbg->regs(i).name) )
      return &regvals[i];
  }
  static regval_t rv;
  return &rv;
}
//-------------------------------------------------------------------------
//</code(py_idp)>
//-------------------------------------------------------------------------

#endif
