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
  int inslen = ph.assemble((uchar *)buf, ea, cs, ip, use32, line);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( inslen > 0 )
    return IDAPyBytes_FromMemAndSize(buf, inslen);
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
  Py_BEGIN_ALLOW_THREADS;
  int inslen = ph.assemble((uchar *)buf, ea, cs, ip, use32, line);
  if ( inslen > 0 )
  {
    patch_bytes(ea, buf, inslen);
    rc = true;
  }
  Py_END_ALLOW_THREADS;
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
  return ph.id;
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
  return ph.version;
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
  return ph.flag;
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
  return ph.cnbits;
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
  return ph.dnbits;
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
  return ph.reg_first_sreg;
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
  return ph.reg_last_sreg;
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
  return ph.segreg_size;
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
  return ph.reg_code_sreg;
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
  return ph.reg_data_sreg;
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
  return ph.icode_return;
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
  return ph.instruc_start;
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
  return ph.instruc_end;
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
  return ph.tbyte_size;
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
  PyObject *py_result = PyTuple_New(ph.instruc_end - ph.instruc_start);
  for ( const instruc_t *p = ph.instruc + ph.instruc_start, *end = ph.instruc + ph.instruc_end;
        p != end;
        ++p )
  {
    PyTuple_SetItem(py_result, i++, Py_BuildValue("(sI)", p->name, p->feature));
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
  Py_ssize_t i = 0;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyObject *py_result = PyList_New(ph.regs_num);
  for ( Py_ssize_t i=0; i < ph.regs_num; i++ )
    PyList_SetItem(py_result, i, IDAPyStr_FromUTF8(ph.reg_names[i]));
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
  Py_BEGIN_ALLOW_THREADS;
  do
  {
    if ( dbg == NULL || n == - 1 )
      break;

    // Allocate register space
    thid_t tid = get_current_thread();
    regvals_t regvalues;
    regvalues.resize(dbg->nregs);
    // Read registers
    if ( get_reg_vals(tid, -1, regvalues.begin()) != DRC_OK )
      break;

    // Call the processor module
    if ( ph.notify(ph.ev_get_idd_opinfo,
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

  Py_END_ALLOW_THREADS;
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
static void ph_calcrel(bytevec_t *vout, ea_t ea)
{
  ph.calcrel(vout, ea);
}

//-------------------------------------------------------------------------
static ssize_t ph_find_reg_value(uval_t *out, const insn_t &insn, int reg)
{
  return ph.find_reg_value(out, insn, reg);
}

//-------------------------------------------------------------------------
static ssize_t ph_find_op_value(uval_t *out, const insn_t &insn, int op)
{
  return ph.find_op_value(out, insn, op);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
class IDP_Hooks(object):
    def hook(self):
        """
        Creates an IDP hook

        @return: Boolean true on success
        """
        pass


    def unhook(self):
        """
        Removes the IDP hook
        @return: Boolean true on success
        """
        pass


    def ev_ana_insn(self, insn):
        """
        Analyzes and decodes an instruction at insn.ea
           - insn.itype must be set >= idaapi.CUSTOM_CMD_ITYPE
           - insn.size must be set to the instruction length

        @return: Boolean
            - False if the instruction is not recognized
            - True if the instruction was decoded. 'insn' should be filled in that case.
        """
        pass


    def ev_out_insn(self, ctx):
        """
        Outputs the instruction defined in 'ctx.insn'

        @return: Boolean (whether this instruction can be outputted or not)
        """
        pass


    def ev_emu_insn(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.

        @return: Boolean (whether this instruction has been emulated or not)
        """
        pass


    def ev_out_operand(self, ctx, op):
        """
        Notification to generate operand text.
        If False was returned, then the standard operand output function will be called.

        this notification may use out_...() functions to form the operand text

        @return: Boolean (whether the operand has been outputted or not)
        """
        pass

    def ev_gen_mnem(self, ctx):
        """
        Notification to generate instruction mnemonics.

        @return:
            - None: No custom mnemonics. IDA will generate a mnemonic name
            - 1: Generated the instruction mnemonics
        """
        pass


    def ev_is_sane_insn(self, insn, no_crefs):
       """
       is the instruction sane for the current file type?
       @param insn: the instruction
       @param no_crefs:
             - 1: the instruction has no code refs to it.
                  ida just tries to convert unexplored bytes
                  to an instruction (but there is no other
                  reason to convert them into an instruction)
             - 0: the instruction is created because
                  of some coderef, user request or another
                  weighty reason.
       @return: >=0-ok, <0-no, the instruction isn't likely to appear in the program
       """
       pass


    def ev_may_be_func(self, insn, state):
       """
       Can a function start here?
       @param insn: the instruction
       @param state: autoanalysis phase
             0: creating functions
             1: creating chunks

       @return: integer (probability 0..100)
       """
       pass


    def ev_rename(self, ea, new_name):
       """
       The kernel is going to rename a byte.

       @param ea: Address
       @param new_name: The new name

       @return:
           - If returns value <0, then the kernel should
             not rename it. See also the 'renamed' event
       """
       pass


    def ev_undefine(self, ea):
       """
       An item in the database (insn or data) is being deleted
       @param ea: Address
       @return:
           - 1 - do not delete srranges at the item end
           - 0 - srranges can be deleted
       """
       pass


    def ev_is_call_insn(self, insn):
       """
       Is the instruction a "call"?

       @param insn: instruction
       @return: 0-unknown, 1-yes, -1-no
       """
       pass


    def ev_is_ret_insn(self, insn, strict):
       """
       Is the instruction a "return"?

       @param insn: instruction
       @param strict: - True: report only ret instructions
                        False: include instructions like "leave" which begins the function epilog
       @return: 0-unknown, 1-yes, -1-no
       """
       pass


    def ev_assemble(self, ea, cs, ip, use32, line):
       """
       Assembles an instruction

       @param ea: linear address of instruction
       @param cs: cs of instruction
       @param ip: ip of instruction
       @param use32: is 32bit segment?
       @param line: line to assemble

       @return: - None to let the underlying processor module assemble the line
                - or a string containing the assembled buffer
       """
       pass

#</pydoc>
*/
//---------------------------------------------------------------------------
// IDP hooks
//---------------------------------------------------------------------------

// Necessary forward declarations; idp.hpp itself doesn't need them.
struct mblock_t;
struct proc_def;
struct libfunc_t;

ssize_t idaapi IDP_Callback(void *ud, int notification_code, va_list va);
class IDP_Hooks
{
  friend ssize_t idaapi IDP_Callback(void *ud, int notification_code, va_list va);
  static ssize_t bool_to_insn_t_size(bool in, const insn_t *insn) { return in ? insn->size : 0; }
  static ssize_t bool_to_1or0(bool in) { return in ? 1 : 0; }
  static ssize_t cm_t_to_ssize_t(cm_t cm) { return ssize_t(cm); }
  static bool _handle_qstring_output(PyObject *o, qstring *buf)
  {
    bool is_str = o != NULL && IDAPyStr_Check(o);
    if ( is_str && buf != NULL )
      IDAPyStr_AsUTF8(buf, o);
    Py_XDECREF(o);
    return is_str;
  }
  static ssize_t handle_custom_mnem_output(PyObject *o, qstring *out, const insn_t *)
  {
    return _handle_qstring_output(o, out) && !out->empty() ? 1 : 0;
  }
  static ssize_t handle_assemble_output(PyObject *o, uchar *bin, ea_t /*ea*/, ea_t /*cs*/, ea_t /*ip*/, bool /*use32*/, const char */*line*/)
  {
    ssize_t rc = 0;
    if ( o != NULL && IDAPyBytes_Check(o) )
    {
      char *s;
      Py_ssize_t len = 0;
      if ( IDAPyBytes_AsMemAndSize(o, &s, &len) != -1 )
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
      if ( PyW_GetNumber(py_ea.o, &nea, NULL)
        && PyBool_Check(py_bexec.o)
        && PyBool_Check(py_fexec.o) )
      {
        if ( pea != NULL )
          *pea = nea;
        if ( pbexec != NULL )
          *pbexec = py_bexec.o == Py_True;
        if ( pfexec != NULL )
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
      if ( IDAPyInt_Check(py_rc.o) && IDAPyInt_Check(py_idx.o) )
      {
        rc = IDAPyInt_AsLong(py_rc.o);
        *idx = IDAPyInt_AsLong(py_idx.o);
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
      if ( IDAPyInt_Check(py_rc.o)
        && IDAPyInt_Check(py_out_res.o)
        && IDAPyStr_Check(py_out.o)
        && IDAPyStr_AsUTF8(&qs, py_out.o) )
      {
        rc = IDAPyInt_AsLong(py_rc.o);
        *out_res = IDAPyInt_AsLong(py_out_res.o);
        if ( out != NULL )
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

public:
  virtual ~IDP_Hooks()
  {
    unhook();
  }

  bool hook()
  {
    return idapython_hook_to_notification_point(HT_IDP, IDP_Callback, this, false);
  }

  bool unhook()
  {
    return idapython_unhook_from_notification_point(HT_IDP, IDP_Callback, this);
  }
  // hookgenIDP:methods
};
//</inline(py_idp)>

//-------------------------------------------------------------------------
//<code(py_idp)>
//-------------------------------------------------------------------------
ssize_t idaapi IDP_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  IDP_Hooks *proxy = (IDP_Hooks *)ud;
  ssize_t ret = 0;
  try
  {
    switch ( notification_code )
    {
      // hookgenIDP:notifications
    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in IDP Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return ret;
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
