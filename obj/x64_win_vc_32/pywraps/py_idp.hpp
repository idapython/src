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
    return IDAPyStr_FromUTF8AndSize(buf, inslen);
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
    if ( o != NULL && IDAPyStr_Check(o) )
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
          const char *name,
          uint32 disable_mask,
          demreq_type_t demreq)
  {
    ssize_t rc = 0;
    if ( PySequence_Check(o) && PySequence_Size(o) == 3 )
    {
      newref_t py_rc(PySequence_GetItem(o, 0));
      newref_t py_out(PySequence_GetItem(o, 1));
      newref_t py_out_res(PySequence_GetItem(o, 2));
      char *s;
      Py_ssize_t len = 0;
      if ( IDAPyInt_Check(py_rc.o)
        && IDAPyInt_Check(py_out_res.o)
        && IDAPyStr_Check(py_out.o)
        && IDAPyBytes_AsMemAndSize(py_out.o, &s, &len) != -1 )
      {
        rc = IDAPyInt_AsLong(py_rc.o);
        *out_res = IDAPyInt_AsLong(py_out_res.o);
        if ( out != NULL )
        {
          out->qclear();
          out->append(s, len);
        }
      }
    }
    return rc;
  }
  static ssize_t handle_find_value_output(
          PyObject *o,
          uval_t *out,
          const insn_t *pinsn,
          int reg)
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
    return idapython_hook_to_notification_point(HT_IDP, IDP_Callback, this);
  }

  bool unhook()
  {
    return idapython_unhook_from_notification_point(HT_IDP, IDP_Callback, this);
  }
  // hookgenIDP:methods
virtual int ev_init(const char * idp_modname) {qnotused(idp_modname); return 0;}
virtual int ev_term() {return 0;}
virtual int ev_newprc(int pnum, bool keep_cfg) {qnotused(pnum); qnotused(keep_cfg); return 0;}
virtual int ev_newasm(int asmnum) {qnotused(asmnum); return 0;}
virtual int ev_newfile(char * fname) {qnotused(fname); return 0;}
virtual int ev_oldfile(char * fname) {qnotused(fname); return 0;}
virtual int ev_newbinary(char * filename, qoff64_t fileoff, ea_t basepara, ea_t binoff, uint64 nbytes) {qnotused(filename); qnotused(fileoff); qnotused(basepara); qnotused(binoff); qnotused(nbytes); return 0;}
virtual int ev_endbinary(bool ok) {qnotused(ok); return 0;}
virtual int ev_set_idp_options(const char * keyword, int value_type, const void * value, const char ** errbuf) {qnotused(keyword); qnotused(value_type); qnotused(value); qnotused(errbuf); return 0;}
virtual int ev_set_proc_options(const char * options, int confidence) {qnotused(options); qnotused(confidence); return 0;}
virtual bool ev_ana_insn(insn_t * out) {qnotused(out); return false;}
virtual bool ev_emu_insn(const insn_t * insn) {qnotused(insn); return false;}
virtual void ev_out_header(outctx_t * outctx) {qnotused(outctx); }
virtual void ev_out_footer(outctx_t * outctx) {qnotused(outctx); }
virtual int ev_out_segstart(outctx_t * outctx, segment_t * seg) {qnotused(outctx); qnotused(seg); return 0;}
virtual int ev_out_segend(outctx_t * outctx, segment_t * seg) {qnotused(outctx); qnotused(seg); return 0;}
virtual int ev_out_assumes(outctx_t * outctx) {qnotused(outctx); return 0;}
virtual bool ev_out_insn(outctx_t * outctx) {qnotused(outctx); return false;}
virtual int ev_out_mnem(outctx_t * outctx) {qnotused(outctx); return 0;}
virtual bool ev_out_operand(outctx_t * outctx, const op_t * op) {qnotused(outctx); qnotused(op); return false;}
virtual int ev_out_data(outctx_t * outctx, bool analyze_only) {qnotused(outctx); qnotused(analyze_only); return 0;}
virtual int ev_out_label(outctx_t * outctx, const char * colored_name) {qnotused(outctx); qnotused(colored_name); return 0;}
virtual int ev_out_special_item(outctx_t * outctx, uchar segtype) {qnotused(outctx); qnotused(segtype); return 0;}
virtual int ev_gen_stkvar_def(outctx_t * outctx, const member_t * mptr, sval_t v) {qnotused(outctx); qnotused(mptr); qnotused(v); return 0;}
virtual int ev_gen_regvar_def(outctx_t * outctx, regvar_t * v) {qnotused(outctx); qnotused(v); return 0;}
virtual int ev_gen_src_file_lnnum() {return 0;}
virtual int ev_creating_segm(segment_t * seg) {qnotused(seg); return 0;}
virtual int ev_moving_segm(segment_t * seg, ea_t to, int flags) {qnotused(seg); qnotused(to); qnotused(flags); return 0;}
virtual int ev_coagulate(ea_t start_ea) {qnotused(start_ea); return 0;}
virtual int ev_undefine(ea_t ea) {qnotused(ea); return 0;}
virtual int ev_treat_hindering_item(ea_t hindering_item_ea, flags_t new_item_flags, ea_t new_item_ea, asize_t new_item_length) {qnotused(hindering_item_ea); qnotused(new_item_flags); qnotused(new_item_ea); qnotused(new_item_length); return 0;}
virtual int ev_rename(ea_t ea, const char * new_name) {qnotused(ea); qnotused(new_name); return 0;}
virtual int ev_is_far_jump(int icode) {qnotused(icode); return 0;}
virtual int ev_is_sane_insn(const insn_t* insn, int no_crefs) {qnotused(insn); qnotused(no_crefs); return 0;}
virtual int ev_is_cond_insn(const insn_t * insn) {qnotused(insn); return 0;}
virtual int ev_is_call_insn(const insn_t * insn) {qnotused(insn); return 0;}
virtual int ev_is_ret_insn(const insn_t * insn, bool strict) {qnotused(insn); qnotused(strict); return 0;}
virtual int ev_may_be_func(const insn_t* insn, int state) {qnotused(insn); qnotused(state); return 0;}
virtual int ev_is_basic_block_end(const insn_t* insn, bool call_insn_stops_block) {qnotused(insn); qnotused(call_insn_stops_block); return 0;}
virtual int ev_is_indirect_jump(const insn_t* insn) {qnotused(insn); return 0;}
virtual int ev_is_insn_table_jump(const insn_t* insn) {qnotused(insn); return 0;}
virtual int ev_is_switch(switch_info_t * si, const insn_t * insn) {qnotused(si); qnotused(insn); return 0;}
virtual int ev_calc_switch_cases(casevec_t * casevec, eavec_t * targets, ea_t insn_ea, switch_info_t * si) {qnotused(casevec); qnotused(targets); qnotused(insn_ea); qnotused(si); return 0;}
virtual int ev_create_switch_xrefs(ea_t jumpea, const switch_info_t * si) {qnotused(jumpea); qnotused(si); return 0;}
virtual int ev_is_align_insn(ea_t ea) {qnotused(ea); return 0;}
virtual int ev_is_alloca_probe(ea_t ea) {qnotused(ea); return 0;}
virtual PyObject * ev_delay_slot_insn(ea_t ea, bool bexec, bool fexec) {qnotused(ea); qnotused(bexec); qnotused(fexec); Py_RETURN_NONE;}
virtual int ev_is_sp_based(int * mode, const insn_t * insn, const op_t * op) {qnotused(mode); qnotused(insn); qnotused(op); return 0;}
virtual int ev_can_have_type(const op_t * op) {qnotused(op); return 0;}
virtual int ev_cmp_operands(const op_t* op1, const op_t* op2) {qnotused(op1); qnotused(op2); return 0;}
virtual int ev_adjust_refinfo(refinfo_t * ri, ea_t ea, int n, const fixup_data_t * fd) {qnotused(ri); qnotused(ea); qnotused(n); qnotused(fd); return 0;}
virtual int ev_get_operand_string(qstring * buf, const insn_t* insn, int opnum) {qnotused(buf); qnotused(insn); qnotused(opnum); return 0;}
virtual PyObject * ev_get_reg_name(int reg, size_t width, int reghi) {qnotused(reg); qnotused(width); qnotused(reghi); Py_RETURN_NONE;}
virtual int ev_str2reg(const char * regname) {qnotused(regname); return 0;}
virtual int ev_get_autocmt(qstring * buf, const insn_t* insn) {qnotused(buf); qnotused(insn); return 0;}
virtual int ev_get_bg_color(bgcolor_t * color, ea_t ea) {qnotused(color); qnotused(ea); return 0;}
virtual int ev_is_jump_func(func_t * pfn, ea_t * jump_target, ea_t * func_pointer) {qnotused(pfn); qnotused(jump_target); qnotused(func_pointer); return 0;}
virtual void ev_func_bounds(int * possible_return_code, func_t * pfn, ea_t max_func_end_ea) {qnotused(possible_return_code); qnotused(pfn); qnotused(max_func_end_ea); }
virtual int ev_verify_sp(func_t * pfn) {qnotused(pfn); return 0;}
virtual int ev_verify_noreturn(func_t * pfn) {qnotused(pfn); return 0;}
virtual int ev_create_func_frame(func_t * pfn) {qnotused(pfn); return 0;}
virtual int ev_get_frame_retsize(int * frsize, const func_t * pfn) {qnotused(frsize); qnotused(pfn); return 0;}
virtual int ev_get_stkvar_scale_factor() {return 0;}
virtual PyObject * ev_demangle_name(qstring * out, const char * name, uint32 disable_mask, int demreq) {qnotused(out); qnotused(name); qnotused(disable_mask); qnotused(demreq); Py_RETURN_NONE;}
virtual int ev_add_cref(ea_t from, ea_t to, cref_t type) {qnotused(from); qnotused(to); qnotused(type); return 0;}
virtual int ev_add_dref(ea_t from, ea_t to, dref_t type) {qnotused(from); qnotused(to); qnotused(type); return 0;}
virtual int ev_del_cref(ea_t from, ea_t to, bool expand) {qnotused(from); qnotused(to); qnotused(expand); return 0;}
virtual int ev_del_dref(ea_t from, ea_t to) {qnotused(from); qnotused(to); return 0;}
virtual int ev_coagulate_dref(ea_t from, ea_t to, bool may_define, ea_t * code_ea) {qnotused(from); qnotused(to); qnotused(may_define); qnotused(code_ea); return 0;}
virtual int ev_may_show_sreg(ea_t current_ea) {qnotused(current_ea); return 0;}
virtual void ev_auto_queue_empty(atype_t type) {qnotused(type); }
virtual int ev_validate_flirt_func(ea_t start_ea, const char * funcname) {qnotused(start_ea); qnotused(funcname); return 0;}
virtual int ev_adjust_libfunc_ea(const idasgn_t * sig, const libfunc_t * libfun, ea_t * ea) {qnotused(sig); qnotused(libfun); qnotused(ea); return 0;}
virtual PyObject * ev_assemble(ea_t ea, ea_t cs, ea_t ip, bool use32, const char * line) {qnotused(ea); qnotused(cs); qnotused(ip); qnotused(use32); qnotused(line); Py_RETURN_NONE;}
virtual int ev_extract_address(ea_t * out_ea, ea_t screen_ea, const char * string, size_t position) {qnotused(out_ea); qnotused(screen_ea); qnotused(string); qnotused(position); return 0;}
virtual int ev_realcvt(void * m, uint16 * e, uint16 swt) {qnotused(m); qnotused(e); qnotused(swt); return 0;}
virtual void ev_gen_asm_or_lst(bool starting, FILE * fp, bool is_asm, int flags, gen_outline_t ** outline) {qnotused(starting); qnotused(fp); qnotused(is_asm); qnotused(flags); qnotused(outline); }
virtual int ev_gen_map_file(int * nlines, FILE * fp) {qnotused(nlines); qnotused(fp); return 0;}
virtual int ev_create_flat_group(ea_t image_base, int bitness, sel_t dataseg_sel) {qnotused(image_base); qnotused(bitness); qnotused(dataseg_sel); return 0;}
virtual int ev_getreg(uval_t * regval, int regnum) {qnotused(regval); qnotused(regnum); return 0;}
virtual int ev_analyze_prolog(ea_t ea) {qnotused(ea); return 0;}
virtual int ev_calc_spdelta(sval_t * spdelta, const insn_t * insn) {qnotused(spdelta); qnotused(insn); return 0;}
virtual int ev_calcrel() {return 0;}
virtual PyObject * ev_find_reg_value(const insn_t * pinsn, int reg) {qnotused(pinsn); qnotused(reg); Py_RETURN_NONE;}
virtual PyObject * ev_find_op_value(const insn_t * pinsn, int opn) {qnotused(pinsn); qnotused(opn); Py_RETURN_NONE;}
virtual int ev_next_exec_insn(ea_t * target, ea_t ea, int tid, processor_t::regval_getter_t * getreg, const regval_t * regvalues) {qnotused(target); qnotused(ea); qnotused(tid); qnotused(getreg); qnotused(regvalues); return 0;}
virtual int ev_calc_step_over(ea_t * target, ea_t ip) {qnotused(target); qnotused(ip); return 0;}
virtual int ev_calc_next_eas(eavec_t * res, const insn_t* insn, bool over) {qnotused(res); qnotused(insn); qnotused(over); return 0;}
virtual int ev_get_macro_insn_head(ea_t * head, ea_t ip) {qnotused(head); qnotused(ip); return 0;}
virtual int ev_get_dbr_opnum(int * opnum, const insn_t* insn) {qnotused(opnum); qnotused(insn); return 0;}
virtual int ev_insn_reads_tbit(const insn_t* insn, processor_t::regval_getter_t * getreg, const regval_t * regvalues) {qnotused(insn); qnotused(getreg); qnotused(regvalues); return 0;}
virtual int ev_clean_tbit(ea_t ea, processor_t::regval_getter_t * getreg, const regval_t * regvalues) {qnotused(ea); qnotused(getreg); qnotused(regvalues); return 0;}
virtual int ev_get_reg_info(const char ** main_regname, bitrange_t * bitrange, const char * regname) {qnotused(main_regname); qnotused(bitrange); qnotused(regname); return 0;}
virtual void ev_setup_til() {}
virtual int ev_get_abi_info(qstrvec_t * abi_names, qstrvec_t * abi_opts, comp_t comp) {qnotused(abi_names); qnotused(abi_opts); qnotused(comp); return 0;}
virtual int ev_max_ptr_size() {return 0;}
virtual int ev_get_default_enum_size(cm_t cm) {qnotused(cm); return 0;}
virtual int ev_get_cc_regs(callregs_t * regs, cm_t cc) {qnotused(regs); qnotused(cc); return 0;}
virtual int ev_get_stkarg_offset() {return 0;}
virtual int ev_shadow_args_size(int * shadow_args_size, func_t * pfn) {qnotused(shadow_args_size); qnotused(pfn); return 0;}
virtual int ev_get_simd_types(simd_info_vec_t * out, const simd_info_t * simd_attrs, const argloc_t * argloc, bool create_tifs) {qnotused(out); qnotused(simd_attrs); qnotused(argloc); qnotused(create_tifs); return 0;}
virtual int ev_calc_cdecl_purged_bytes(ea_t ea) {qnotused(ea); return 0;}
virtual int ev_calc_purged_bytes(int * p_purged_bytes, const func_type_data_t * fti) {qnotused(p_purged_bytes); qnotused(fti); return 0;}
virtual int ev_calc_retloc(argloc_t * retloc, const tinfo_t * rettype, cm_t cc) {qnotused(retloc); qnotused(rettype); qnotused(cc); return 0;}
virtual int ev_calc_arglocs(func_type_data_t * fti) {qnotused(fti); return 0;}
virtual int ev_calc_varglocs(func_type_data_t * ftd, regobjs_t * regs, relobj_t * stkargs, int nfixed) {qnotused(ftd); qnotused(regs); qnotused(stkargs); qnotused(nfixed); return 0;}
virtual int ev_adjust_argloc(argloc_t * argloc, const tinfo_t * optional_type, int size) {qnotused(argloc); qnotused(optional_type); qnotused(size); return 0;}
virtual int ev_lower_func_type(intvec_t * argnums, func_type_data_t * fti) {qnotused(argnums); qnotused(fti); return 0;}
virtual int ev_equal_reglocs(argloc_t * a1, argloc_t * a2) {qnotused(a1); qnotused(a2); return 0;}
virtual int ev_use_stkarg_type(ea_t ea, const funcarg_t * arg) {qnotused(ea); qnotused(arg); return 0;}
virtual PyObject * ev_use_regarg_type(ea_t ea, const funcargvec_t * rargs) {qnotused(ea); qnotused(rargs); Py_RETURN_NONE;}
virtual int ev_use_arg_types(ea_t ea, func_type_data_t * fti, funcargvec_t * rargs) {qnotused(ea); qnotused(fti); qnotused(rargs); return 0;}
virtual int ev_arg_addrs_ready(ea_t caller, int n, tinfo_t * tif, ea_t * addrs) {qnotused(caller); qnotused(n); qnotused(tif); qnotused(addrs); return 0;}
virtual PyObject * ev_decorate_name(const char * name, bool mangle, int cc, const tinfo_t * optional_type) {qnotused(name); qnotused(mangle); qnotused(cc); qnotused(optional_type); Py_RETURN_NONE;}
virtual int ev_loader() {return 0;}
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
case processor_t::ev_init:
{
  const char * idp_modname = va_arg(va, const char *);
  ret = proxy->ev_init(idp_modname);
}
break;

case processor_t::ev_term:
{
  ret = proxy->ev_term();
}
break;

case processor_t::ev_newprc:
{
  int pnum = va_arg(va, int);
  bool keep_cfg = bool(va_arg(va, int));
  ret = proxy->ev_newprc(pnum, keep_cfg);
}
break;

case processor_t::ev_newasm:
{
  int asmnum = va_arg(va, int);
  ret = proxy->ev_newasm(asmnum);
}
break;

case processor_t::ev_newfile:
{
  char * fname = va_arg(va, char *);
  ret = proxy->ev_newfile(fname);
}
break;

case processor_t::ev_oldfile:
{
  char * fname = va_arg(va, char *);
  ret = proxy->ev_oldfile(fname);
}
break;

case processor_t::ev_newbinary:
{
  char * filename = va_arg(va, char *);
  qoff64_t fileoff = va_arg(va, qoff64_t);
  ea_t basepara = va_arg(va, ea_t);
  ea_t binoff = va_arg(va, ea_t);
  uint64 nbytes = va_arg(va, uint64);
  ret = proxy->ev_newbinary(filename, fileoff, basepara, binoff, nbytes);
}
break;

case processor_t::ev_endbinary:
{
  bool ok = bool(va_arg(va, int));
  ret = proxy->ev_endbinary(ok);
}
break;

case processor_t::ev_set_idp_options:
{
  const char * keyword = va_arg(va, const char *);
  int value_type = va_arg(va, int);
  const void * value = va_arg(va, const void *);
  const char ** errbuf = va_arg(va, const char **);
  ret = proxy->ev_set_idp_options(keyword, value_type, value, errbuf);
}
break;

case processor_t::ev_set_proc_options:
{
  const char * options = va_arg(va, const char *);
  int confidence = va_arg(va, int);
  ret = proxy->ev_set_proc_options(options, confidence);
}
break;

case processor_t::ev_ana_insn:
{
  insn_t * out = va_arg(va, insn_t *);
  bool _tmp = proxy->ev_ana_insn(out);
  ret = IDP_Hooks::bool_to_insn_t_size(_tmp, out);
}
break;

case processor_t::ev_emu_insn:
{
  const insn_t * insn = va_arg(va, const insn_t *);
  bool _tmp = proxy->ev_emu_insn(insn);
  ret = IDP_Hooks::bool_to_1or0(_tmp);
}
break;

case processor_t::ev_out_header:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  proxy->ev_out_header(outctx);
}
break;

case processor_t::ev_out_footer:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  proxy->ev_out_footer(outctx);
}
break;

case processor_t::ev_out_segstart:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  segment_t * seg = va_arg(va, segment_t *);
  ret = proxy->ev_out_segstart(outctx, seg);
}
break;

case processor_t::ev_out_segend:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  segment_t * seg = va_arg(va, segment_t *);
  ret = proxy->ev_out_segend(outctx, seg);
}
break;

case processor_t::ev_out_assumes:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  ret = proxy->ev_out_assumes(outctx);
}
break;

case processor_t::ev_out_insn:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  bool _tmp = proxy->ev_out_insn(outctx);
  ret = IDP_Hooks::bool_to_1or0(_tmp);
}
break;

case processor_t::ev_out_mnem:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  ret = proxy->ev_out_mnem(outctx);
}
break;

case processor_t::ev_out_operand:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  const op_t * op = va_arg(va, const op_t *);
  bool _tmp = proxy->ev_out_operand(outctx, op);
  ret = IDP_Hooks::bool_to_1or0(_tmp);
}
break;

case processor_t::ev_out_data:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  bool analyze_only = bool(va_arg(va, int));
  ret = proxy->ev_out_data(outctx, analyze_only);
}
break;

case processor_t::ev_out_label:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  const char * colored_name = va_arg(va, const char *);
  ret = proxy->ev_out_label(outctx, colored_name);
}
break;

case processor_t::ev_out_special_item:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  uchar segtype = uchar(va_arg(va, int));
  ret = proxy->ev_out_special_item(outctx, segtype);
}
break;

case processor_t::ev_gen_stkvar_def:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  const member_t * mptr = va_arg(va, const member_t *);
  sval_t v = va_arg(va, sval_t);
  ret = proxy->ev_gen_stkvar_def(outctx, mptr, v);
}
break;

case processor_t::ev_gen_regvar_def:
{
  outctx_t * outctx = va_arg(va, outctx_t *);
  regvar_t * v = va_arg(va, regvar_t *);
  ret = proxy->ev_gen_regvar_def(outctx, v);
}
break;

case processor_t::ev_gen_src_file_lnnum:
{
  ret = proxy->ev_gen_src_file_lnnum();
}
break;

case processor_t::ev_creating_segm:
{
  segment_t * seg = va_arg(va, segment_t *);
  ret = proxy->ev_creating_segm(seg);
}
break;

case processor_t::ev_moving_segm:
{
  segment_t * seg = va_arg(va, segment_t *);
  ea_t to = va_arg(va, ea_t);
  int flags = va_arg(va, int);
  ret = proxy->ev_moving_segm(seg, to, flags);
}
break;

case processor_t::ev_coagulate:
{
  ea_t start_ea = va_arg(va, ea_t);
  ret = proxy->ev_coagulate(start_ea);
}
break;

case processor_t::ev_undefine:
{
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->ev_undefine(ea);
}
break;

case processor_t::ev_treat_hindering_item:
{
  ea_t hindering_item_ea = va_arg(va, ea_t);
  flags_t new_item_flags = va_arg(va, flags_t);
  ea_t new_item_ea = va_arg(va, ea_t);
  asize_t new_item_length = va_arg(va, asize_t);
  ret = proxy->ev_treat_hindering_item(hindering_item_ea, new_item_flags, new_item_ea, new_item_length);
}
break;

case processor_t::ev_rename:
{
  ea_t ea = va_arg(va, ea_t);
  const char * new_name = va_arg(va, const char *);
  int flags = va_arg(va, int);
  qnotused(flags);
  ret = proxy->ev_rename(ea, new_name);
}
break;

case processor_t::ev_is_far_jump:
{
  int icode = va_arg(va, int);
  ret = proxy->ev_is_far_jump(icode);
}
break;

case processor_t::ev_is_sane_insn:
{
  const insn_t* insn = va_arg(va, const insn_t*);
  int no_crefs = va_arg(va, int);
  ret = proxy->ev_is_sane_insn(insn, no_crefs);
}
break;

case processor_t::ev_is_cond_insn:
{
  const insn_t * insn = va_arg(va, const insn_t *);
  ret = proxy->ev_is_cond_insn(insn);
}
break;

case processor_t::ev_is_call_insn:
{
  const insn_t * insn = va_arg(va, const insn_t *);
  ret = proxy->ev_is_call_insn(insn);
}
break;

case processor_t::ev_is_ret_insn:
{
  const insn_t * insn = va_arg(va, const insn_t *);
  bool strict = bool(va_arg(va, int));
  ret = proxy->ev_is_ret_insn(insn, strict);
}
break;

case processor_t::ev_may_be_func:
{
  const insn_t* insn = va_arg(va, const insn_t*);
  int state = va_arg(va, int);
  ret = proxy->ev_may_be_func(insn, state);
}
break;

case processor_t::ev_is_basic_block_end:
{
  const insn_t* insn = va_arg(va, const insn_t*);
  bool call_insn_stops_block = bool(va_arg(va, int));
  ret = proxy->ev_is_basic_block_end(insn, call_insn_stops_block);
}
break;

case processor_t::ev_is_indirect_jump:
{
  const insn_t* insn = va_arg(va, const insn_t*);
  ret = proxy->ev_is_indirect_jump(insn);
}
break;

case processor_t::ev_is_insn_table_jump:
{
  const insn_t* insn = va_arg(va, const insn_t*);
  ret = proxy->ev_is_insn_table_jump(insn);
}
break;

case processor_t::ev_is_switch:
{
  switch_info_t * si = va_arg(va, switch_info_t *);
  const insn_t * insn = va_arg(va, const insn_t *);
  ret = proxy->ev_is_switch(si, insn);
}
break;

case processor_t::ev_calc_switch_cases:
{
  casevec_t * casevec = va_arg(va, casevec_t *);
  eavec_t * targets = va_arg(va, eavec_t *);
  ea_t insn_ea = va_arg(va, ea_t);
  switch_info_t * si = va_arg(va, switch_info_t *);
  ret = proxy->ev_calc_switch_cases(casevec, targets, insn_ea, si);
}
break;

case processor_t::ev_create_switch_xrefs:
{
  ea_t jumpea = va_arg(va, ea_t);
  const switch_info_t * si = va_arg(va, const switch_info_t *);
  ret = proxy->ev_create_switch_xrefs(jumpea, si);
}
break;

case processor_t::ev_is_align_insn:
{
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->ev_is_align_insn(ea);
}
break;

case processor_t::ev_is_alloca_probe:
{
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->ev_is_alloca_probe(ea);
}
break;

case processor_t::ev_delay_slot_insn:
{
  ea_t * ea = va_arg(va, ea_t *);
  bool * bexec = va_arg(va, bool *);
  bool * fexec = va_arg(va, bool *);
  PyObject * _tmp = proxy->ev_delay_slot_insn(ea != NULL ? *(ea) : (BADADDR), bexec != NULL ? *(bexec) : (false), fexec != NULL ? *(fexec) : (false));
  ret = IDP_Hooks::handle_delay_slot_insn_output(_tmp, ea, bexec, fexec);
}
break;

case processor_t::ev_is_sp_based:
{
  int * mode = va_arg(va, int *);
  const insn_t * insn = va_arg(va, const insn_t *);
  const op_t * op = va_arg(va, const op_t *);
  ret = proxy->ev_is_sp_based(mode, insn, op);
}
break;

case processor_t::ev_can_have_type:
{
  const op_t * op = va_arg(va, const op_t *);
  ret = proxy->ev_can_have_type(op);
}
break;

case processor_t::ev_cmp_operands:
{
  const op_t* op1 = va_arg(va, const op_t*);
  const op_t* op2 = va_arg(va, const op_t*);
  ret = proxy->ev_cmp_operands(op1, op2);
}
break;

case processor_t::ev_adjust_refinfo:
{
  refinfo_t * ri = va_arg(va, refinfo_t *);
  ea_t ea = va_arg(va, ea_t);
  int n = va_arg(va, int);
  const fixup_data_t * fd = va_arg(va, const fixup_data_t *);
  ret = proxy->ev_adjust_refinfo(ri, ea, n, fd);
}
break;

case processor_t::ev_get_operand_string:
{
  qstring * buf = va_arg(va, qstring *);
  const insn_t* insn = va_arg(va, const insn_t*);
  int opnum = va_arg(va, int);
  ret = proxy->ev_get_operand_string(buf, insn, opnum);
}
break;

case processor_t::ev_get_reg_name:
{
  qstring * buf = va_arg(va, qstring *);
  int reg = va_arg(va, int);
  size_t width = va_arg(va, size_t);
  int reghi = va_arg(va, int);
  PyObject * _tmp = proxy->ev_get_reg_name(reg, width, reghi);
  ret = IDP_Hooks::handle_get_reg_name_output(_tmp, buf, reg, width, reghi);
}
break;

case processor_t::ev_str2reg:
{
  const char * regname = va_arg(va, const char *);
  ret = proxy->ev_str2reg(regname);
}
break;

case processor_t::ev_get_autocmt:
{
  qstring * buf = va_arg(va, qstring *);
  const insn_t* insn = va_arg(va, const insn_t*);
  ret = proxy->ev_get_autocmt(buf, insn);
}
break;

case processor_t::ev_get_bg_color:
{
  bgcolor_t * color = va_arg(va, bgcolor_t *);
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->ev_get_bg_color(color, ea);
}
break;

case processor_t::ev_is_jump_func:
{
  func_t * pfn = va_arg(va, func_t *);
  ea_t * jump_target = va_arg(va, ea_t *);
  ea_t * func_pointer = va_arg(va, ea_t *);
  ret = proxy->ev_is_jump_func(pfn, jump_target, func_pointer);
}
break;

case processor_t::ev_func_bounds:
{
  int * possible_return_code = va_arg(va, int *);
  func_t * pfn = va_arg(va, func_t *);
  ea_t max_func_end_ea = va_arg(va, ea_t);
  proxy->ev_func_bounds(possible_return_code, pfn, max_func_end_ea);
}
break;

case processor_t::ev_verify_sp:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->ev_verify_sp(pfn);
}
break;

case processor_t::ev_verify_noreturn:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->ev_verify_noreturn(pfn);
}
break;

case processor_t::ev_create_func_frame:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->ev_create_func_frame(pfn);
}
break;

case processor_t::ev_get_frame_retsize:
{
  int * frsize = va_arg(va, int *);
  const func_t * pfn = va_arg(va, const func_t *);
  ret = proxy->ev_get_frame_retsize(frsize, pfn);
}
break;

case processor_t::ev_get_stkvar_scale_factor:
{
  ret = proxy->ev_get_stkvar_scale_factor();
}
break;

case processor_t::ev_demangle_name:
{
  int32 * res = va_arg(va, int32 *);
  qstring * out = va_arg(va, qstring *);
  const char * name = va_arg(va, const char *);
  uint32 disable_mask = va_arg(va, uint32);
  demreq_type_t demreq = demreq_type_t(va_arg(va, int));
  PyObject * _tmp = proxy->ev_demangle_name(out, name, disable_mask, (int) demreq);
  ret = IDP_Hooks::handle_demangle_name_output(_tmp, res, out, name, disable_mask, demreq);
}
break;

case processor_t::ev_add_cref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  cref_t type = cref_t(va_arg(va, int));
  ret = proxy->ev_add_cref(from, to, type);
}
break;

case processor_t::ev_add_dref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  dref_t type = dref_t(va_arg(va, int));
  ret = proxy->ev_add_dref(from, to, type);
}
break;

case processor_t::ev_del_cref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  bool expand = bool(va_arg(va, int));
  ret = proxy->ev_del_cref(from, to, expand);
}
break;

case processor_t::ev_del_dref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  ret = proxy->ev_del_dref(from, to);
}
break;

case processor_t::ev_coagulate_dref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  bool may_define = bool(va_arg(va, int));
  ea_t * code_ea = va_arg(va, ea_t *);
  ret = proxy->ev_coagulate_dref(from, to, may_define, code_ea);
}
break;

case processor_t::ev_may_show_sreg:
{
  ea_t current_ea = va_arg(va, ea_t);
  ret = proxy->ev_may_show_sreg(current_ea);
}
break;

case processor_t::ev_auto_queue_empty:
{
  atype_t type = va_arg(va, atype_t);
  proxy->ev_auto_queue_empty(type);
}
break;

case processor_t::ev_validate_flirt_func:
{
  ea_t start_ea = va_arg(va, ea_t);
  const char * funcname = va_arg(va, const char *);
  ret = proxy->ev_validate_flirt_func(start_ea, funcname);
}
break;

case processor_t::ev_adjust_libfunc_ea:
{
  const idasgn_t * sig = va_arg(va, const idasgn_t *);
  const libfunc_t * libfun = va_arg(va, const libfunc_t *);
  ea_t * ea = va_arg(va, ea_t *);
  ret = proxy->ev_adjust_libfunc_ea(sig, libfun, ea);
}
break;

case processor_t::ev_assemble:
{
  uchar * bin = va_arg(va, uchar *);
  ea_t ea = va_arg(va, ea_t);
  ea_t cs = va_arg(va, ea_t);
  ea_t ip = va_arg(va, ea_t);
  bool use32 = bool(va_arg(va, int));
  const char * line = va_arg(va, const char *);
  PyObject * _tmp = proxy->ev_assemble(ea, cs, ip, use32, line);
  ret = IDP_Hooks::handle_assemble_output(_tmp, bin, ea, cs, ip, use32, line);
}
break;

case processor_t::ev_extract_address:
{
  ea_t * out_ea = va_arg(va, ea_t *);
  ea_t screen_ea = va_arg(va, ea_t);
  const char * string = va_arg(va, const char *);
  size_t position = va_arg(va, size_t);
  ret = proxy->ev_extract_address(out_ea, screen_ea, string, position);
}
break;

case processor_t::ev_realcvt:
{
  void * m = va_arg(va, void *);
  uint16 * e = va_arg(va, uint16 *);
  uint16 swt = uint16(va_arg(va, int));
  ret = proxy->ev_realcvt(m, e, swt);
}
break;

case processor_t::ev_gen_asm_or_lst:
{
  bool starting = bool(va_arg(va, int));
  FILE * fp = va_arg(va, FILE *);
  bool is_asm = bool(va_arg(va, int));
  int flags = va_arg(va, int);
  gen_outline_t ** outline = va_arg(va, gen_outline_t **);
  proxy->ev_gen_asm_or_lst(starting, fp, is_asm, flags, outline);
}
break;

case processor_t::ev_gen_map_file:
{
  int * nlines = va_arg(va, int *);
  FILE * fp = va_arg(va, FILE *);
  ret = proxy->ev_gen_map_file(nlines, fp);
}
break;

case processor_t::ev_create_flat_group:
{
  ea_t image_base = va_arg(va, ea_t);
  int bitness = va_arg(va, int);
  sel_t dataseg_sel = va_arg(va, sel_t);
  ret = proxy->ev_create_flat_group(image_base, bitness, dataseg_sel);
}
break;

case processor_t::ev_getreg:
{
  uval_t * regval = va_arg(va, uval_t *);
  int regnum = va_arg(va, int);
  ret = proxy->ev_getreg(regval, regnum);
}
break;

case processor_t::ev_analyze_prolog:
{
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->ev_analyze_prolog(ea);
}
break;

case processor_t::ev_calc_spdelta:
{
  sval_t * spdelta = va_arg(va, sval_t *);
  const insn_t * insn = va_arg(va, const insn_t *);
  ret = proxy->ev_calc_spdelta(spdelta, insn);
}
break;

case processor_t::ev_calcrel:
{
  ret = proxy->ev_calcrel();
}
break;

case processor_t::ev_find_reg_value:
{
  uval_t * out = va_arg(va, uval_t *);
  const insn_t * pinsn = va_arg(va, const insn_t *);
  int reg = va_arg(va, int);
  PyObject * _tmp = proxy->ev_find_reg_value(pinsn, reg);
  ret = IDP_Hooks::handle_find_value_output(_tmp, out, pinsn, reg);
}
break;

case processor_t::ev_find_op_value:
{
  uval_t * out = va_arg(va, uval_t *);
  const insn_t * pinsn = va_arg(va, const insn_t *);
  int opn = va_arg(va, int);
  PyObject * _tmp = proxy->ev_find_op_value(pinsn, opn);
  ret = IDP_Hooks::handle_find_value_output(_tmp, out, pinsn, opn);
}
break;

case processor_t::ev_next_exec_insn:
{
  ea_t * target = va_arg(va, ea_t *);
  ea_t ea = va_arg(va, ea_t);
  int tid = va_arg(va, int);
  processor_t::regval_getter_t * getreg = va_arg(va, processor_t::regval_getter_t *);
  const regval_t * regvalues = va_arg(va, const regval_t *);
  ret = proxy->ev_next_exec_insn(target, ea, tid, getreg, regvalues);
}
break;

case processor_t::ev_calc_step_over:
{
  ea_t * target = va_arg(va, ea_t *);
  ea_t ip = va_arg(va, ea_t);
  ret = proxy->ev_calc_step_over(target, ip);
}
break;

case processor_t::ev_calc_next_eas:
{
  eavec_t * res = va_arg(va, eavec_t *);
  const insn_t* insn = va_arg(va, const insn_t*);
  bool over = bool(va_arg(va, int));
  ret = proxy->ev_calc_next_eas(res, insn, over);
}
break;

case processor_t::ev_get_macro_insn_head:
{
  ea_t * head = va_arg(va, ea_t *);
  ea_t ip = va_arg(va, ea_t);
  ret = proxy->ev_get_macro_insn_head(head, ip);
}
break;

case processor_t::ev_get_dbr_opnum:
{
  int * opnum = va_arg(va, int *);
  const insn_t* insn = va_arg(va, const insn_t*);
  ret = proxy->ev_get_dbr_opnum(opnum, insn);
}
break;

case processor_t::ev_insn_reads_tbit:
{
  const insn_t* insn = va_arg(va, const insn_t*);
  processor_t::regval_getter_t * getreg = va_arg(va, processor_t::regval_getter_t *);
  const regval_t * regvalues = va_arg(va, const regval_t *);
  ret = proxy->ev_insn_reads_tbit(insn, getreg, regvalues);
}
break;

case processor_t::ev_clean_tbit:
{
  ea_t ea = va_arg(va, ea_t);
  processor_t::regval_getter_t * getreg = va_arg(va, processor_t::regval_getter_t *);
  const regval_t * regvalues = va_arg(va, const regval_t *);
  ret = proxy->ev_clean_tbit(ea, getreg, regvalues);
}
break;

case processor_t::ev_get_reg_info:
{
  const char ** main_regname = va_arg(va, const char **);
  bitrange_t * bitrange = va_arg(va, bitrange_t *);
  const char * regname = va_arg(va, const char *);
  ret = proxy->ev_get_reg_info(main_regname, bitrange, regname);
}
break;

case processor_t::ev_setup_til:
{
  proxy->ev_setup_til();
}
break;

case processor_t::ev_get_abi_info:
{
  qstrvec_t * abi_names = va_arg(va, qstrvec_t *);
  qstrvec_t * abi_opts = va_arg(va, qstrvec_t *);
  comp_t comp = va_arg(va, comp_t);
  ret = proxy->ev_get_abi_info(abi_names, abi_opts, comp);
}
break;

case processor_t::ev_max_ptr_size:
{
  ret = proxy->ev_max_ptr_size();
}
break;

case processor_t::ev_get_default_enum_size:
{
  cm_t cm = cm_t(va_arg(va, int));
  ret = proxy->ev_get_default_enum_size(cm);
}
break;

case processor_t::ev_get_cc_regs:
{
  callregs_t * regs = va_arg(va, callregs_t *);
  cm_t cc = cm_t(va_arg(va, int));
  ret = proxy->ev_get_cc_regs(regs, cc);
}
break;

case processor_t::ev_get_stkarg_offset:
{
  ret = proxy->ev_get_stkarg_offset();
}
break;

case processor_t::ev_shadow_args_size:
{
  int * shadow_args_size = va_arg(va, int *);
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->ev_shadow_args_size(shadow_args_size, pfn);
}
break;

case processor_t::ev_get_simd_types:
{
  simd_info_vec_t * out = va_arg(va, simd_info_vec_t *);
  const simd_info_t * simd_attrs = va_arg(va, const simd_info_t *);
  const argloc_t * argloc = va_arg(va, const argloc_t *);
  bool create_tifs = bool(va_arg(va, int));
  ret = proxy->ev_get_simd_types(out, simd_attrs, argloc, create_tifs);
}
break;

case processor_t::ev_calc_cdecl_purged_bytes:
{
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->ev_calc_cdecl_purged_bytes(ea);
}
break;

case processor_t::ev_calc_purged_bytes:
{
  int * p_purged_bytes = va_arg(va, int *);
  const func_type_data_t * fti = va_arg(va, const func_type_data_t *);
  ret = proxy->ev_calc_purged_bytes(p_purged_bytes, fti);
}
break;

case processor_t::ev_calc_retloc:
{
  argloc_t * retloc = va_arg(va, argloc_t *);
  const tinfo_t * rettype = va_arg(va, const tinfo_t *);
  cm_t cc = cm_t(va_arg(va, int));
  ret = proxy->ev_calc_retloc(retloc, rettype, cc);
}
break;

case processor_t::ev_calc_arglocs:
{
  func_type_data_t * fti = va_arg(va, func_type_data_t *);
  ret = proxy->ev_calc_arglocs(fti);
}
break;

case processor_t::ev_calc_varglocs:
{
  func_type_data_t * ftd = va_arg(va, func_type_data_t *);
  regobjs_t * regs = va_arg(va, regobjs_t *);
  relobj_t * stkargs = va_arg(va, relobj_t *);
  int nfixed = va_arg(va, int);
  ret = proxy->ev_calc_varglocs(ftd, regs, stkargs, nfixed);
}
break;

case processor_t::ev_adjust_argloc:
{
  argloc_t * argloc = va_arg(va, argloc_t *);
  const tinfo_t * type = va_arg(va, const tinfo_t *);
  int size = va_arg(va, int);
  ret = proxy->ev_adjust_argloc(argloc, type, size);
}
break;

case processor_t::ev_lower_func_type:
{
  intvec_t * argnums = va_arg(va, intvec_t *);
  func_type_data_t * fti = va_arg(va, func_type_data_t *);
  ret = proxy->ev_lower_func_type(argnums, fti);
}
break;

case processor_t::ev_equal_reglocs:
{
  argloc_t * a1 = va_arg(va, argloc_t *);
  argloc_t * a2 = va_arg(va, argloc_t *);
  ret = proxy->ev_equal_reglocs(a1, a2);
}
break;

case processor_t::ev_use_stkarg_type:
{
  ea_t ea = va_arg(va, ea_t);
  const funcarg_t * arg = va_arg(va, const funcarg_t *);
  ret = proxy->ev_use_stkarg_type(ea, arg);
}
break;

case processor_t::ev_use_regarg_type:
{
  int * idx = va_arg(va, int *);
  ea_t ea = va_arg(va, ea_t);
  const funcargvec_t * rargs = va_arg(va, const funcargvec_t *);
  PyObject * _tmp = proxy->ev_use_regarg_type(ea, rargs);
  ret = IDP_Hooks::handle_use_regarg_type_output(_tmp, idx, ea, rargs);
}
break;

case processor_t::ev_use_arg_types:
{
  ea_t ea = va_arg(va, ea_t);
  func_type_data_t * fti = va_arg(va, func_type_data_t *);
  funcargvec_t * rargs = va_arg(va, funcargvec_t *);
  ret = proxy->ev_use_arg_types(ea, fti, rargs);
}
break;

case processor_t::ev_arg_addrs_ready:
{
  ea_t caller = va_arg(va, ea_t);
  int n = va_arg(va, int);
  tinfo_t * tif = va_arg(va, tinfo_t *);
  ea_t * addrs = va_arg(va, ea_t *);
  ret = proxy->ev_arg_addrs_ready(caller, n, tif, addrs);
}
break;

case processor_t::ev_decorate_name:
{
  qstring * outbuf = va_arg(va, qstring *);
  const char * name = va_arg(va, const char *);
  bool mangle = bool(va_arg(va, int));
  cm_t cc = cm_t(va_arg(va, int));
  const tinfo_t * type = va_arg(va, const tinfo_t *);
  PyObject * _tmp = proxy->ev_decorate_name(name, mangle, IDP_Hooks::cm_t_to_ssize_t(cc), type);
  ret = IDP_Hooks::handle_decorate_name3_output(_tmp, outbuf, name, mangle, cc, type);
}
break;

case processor_t::ev_loader:
{
  ret = proxy->ev_loader();
}
break;

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
