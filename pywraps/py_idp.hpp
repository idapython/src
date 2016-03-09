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
  int inslen;
  char buf[MAXSTR];
  bool ok = false;
  if ( ph.notify != NULL
    && (inslen = ph.notify(ph.assemble, ea, cs, ip, use32, line, buf)) > 0 )
  {
    ok = true;
  }
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ok )
    return PyString_FromStringAndSize(buf, inslen);
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
  int inslen;
  char buf[MAXSTR];
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc = false;
  Py_BEGIN_ALLOW_THREADS;
  if ( ph.notify != NULL )
  {
    inslen = ph.notify(ph.assemble, ea, cs, ip, use32, line, buf);
    if ( inslen > 0 )
    {
      patch_many_bytes(ea, buf, inslen);
      rc = true;
    }
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
def ph_get_regFirstSreg():
    """
    Returns the 'ph.regFirstSreg'
    """
    pass
#</pydoc>
*/
static size_t ph_get_regFirstSreg()
{
  return ph.regFirstSreg;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_regLastSreg():
    """
    Returns the 'ph.regLastSreg'
    """
    pass
#</pydoc>
*/
static size_t ph_get_regLastSreg()
{
  return ph.regLastSreg;
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
def ph_get_regCodeSreg():
    """
    Returns the 'ph.regCodeSreg'
    """
    pass
#</pydoc>
*/
static size_t ph_get_regCodeSreg()
{
  return ph.regCodeSreg;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_regDataSreg():
    """
    Returns the 'ph.regDataSreg'
    """
    pass
#</pydoc>
*/
static size_t ph_get_regDataSreg()
{
  return ph.regDataSreg;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def ph_get_high_fixup_bits():
    """
    Returns the 'ph.high_fixup_bits'
    """
    pass
#</pydoc>
*/
static size_t ph_get_high_fixup_bits()
{
  return ph.high_fixup_bits;
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
  PyObject *py_result = PyList_New(ph.regsNum);
  for ( Py_ssize_t i=0; i<ph.regsNum; i++ )
    PyList_SetItem(py_result, i, PyString_FromString(ph.regNames[i]));
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
    regvalues.resize(dbg->registers_size);
    // Read registers
    if ( get_reg_vals(tid, -1, regvalues.begin()) != 1 )
      break;

    // Call the processor module
    if ( ph.notify(ph.get_operand_info,
              ea,
              n,
              tid,
              _py_getreg,
              regvalues.begin(),
              &opinf) > 0 )
    {
      break;
    }
    ok = true;
  } while (false);

  Py_END_ALLOW_THREADS;
  if ( ok )
    return Py_BuildValue("(i" PY_FMT64 "Kii)",
                         opinf.modified,
                         opinf.ea,
                         opinf.value.ival,
                         opinf.debregidx,
                         opinf.value_size);
  else
    Py_RETURN_NONE;
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


    def custom_ana(self):
        """
        Analyzes and decodes an instruction at idaapi.cmd.ea
           - cmd.itype must be set >= idaapi.CUSTOM_CMD_ITYPE
           - cmd.size must be set to the instruction length

        @return: Boolean
            - False if the instruction is not recognized
            - True if the instruction was decoded. idaapi.cmd should be filled in that case.
        """
        pass


    def custom_out(self):
        """
        Outputs the instruction defined in idaapi.cmd

        @return: Boolean (whether this instruction can be outputted or not)
        """
        pass


    def custom_emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.

        @return: Boolean (whether this instruction has been emulated or not)
        """
        pass


    def custom_outop(self, op):
        """
        Notification to generate operand text.
        If False was returned, then the standard operand output function will be called.

        The output buffer is inited with init_output_buffer()
        and this notification may use out_...() functions to form the operand text

        @return: Boolean (whether the operand has been outputted or not)
        """
        pass

    def custom_mnem(self):
        """
        Prints the mnemonic of the instruction defined in idaapi.cmd

        @return:
            - None: No mnemonic. IDA will use the default mnemonic value if present
            - String: The desired mnemonic string
        """
        pass


    def is_sane_insn(self, no_crefs):
       """
       is the instruction sane for the current file type?
       @param no_crefs:
             - 1: the instruction has no code refs to it.
                  ida just tries to convert unexplored bytes
                  to an instruction (but there is no other
                  reason to convert them into an instruction)
             - 0: the instruction is created because
                  of some coderef, user request or another
                  weighty reason.
       @return: 1-ok, <=0-no, the instruction isn't likely to appear in the program
       """
       pass


    def may_be_func(self, no_crefs):
       """
       Can a function start here?
       @param state: autoanalysis phase
             0: creating functions
             1: creating chunks

       @return: integer (probability 0..100)
       """
       pass


    def closebase(self):
       """
       The database will be closed now
       """
       pass


    def savebase(self):
       """
       The database is being saved. Processor module should
       """
       pass


    def rename(self, ea, new_name):
       """
       The kernel is going to rename a byte.

       @param ea: Address
       @param new_name: The new name

       @return:
           - If returns value <=0, then the kernel should
             not rename it. See also the 'renamed' event
       """
       pass


    def renamed(self, ea, new_name, local_name):
       """
       The kernel has renamed a byte

       @param ea: Address
       @param new_name: The new name
       @param local_name: Is local name

       @return: Ignored
       """
       pass


    def undefine(self, ea):
       """
       An item in the database (insn or data) is being deleted
       @param ea: Address
       @return:
           - returns: >0-ok, <=0-the kernel should stop
           - if the return value is positive:
              bit0 - ignored
              bit1 - do not delete srareas at the item end
       """
       pass


    def make_code(self, ea, size):
       """
       An instruction is being created
       @param ea: Address
       @param size: Instruction size
       @return: 1-ok, <=0-the kernel should stop
       """
       pass


    def make_code(self, ea, size):
       """
       An instruction is being created
       @param ea: Address
       @param size: Instruction size
       @return: 1-ok, <=0-the kernel should stop
       """
       pass


    def make_data(self, ea, flags, tid, len):
       """
       A data item is being created
       @param ea: Address
       @param tid: type id
       @param flags: item flags
       @param len: data item size
       @return: 1-ok, <=0-the kernel should stop
       """
       pass


    def load_idasgn(self, short_sig_name):
       """
       FLIRT signature have been loaded for normal processing
       (not for recognition of startup sequences)
       @param short_sig_name: signature name
       @return: Ignored
       """
       pass


    def add_func(self, func):
       """
       The kernel has added a function
       @param func: the func_t instance
       @return: Ignored
       """
       pass


    def del_func(self, func):
       """
       The kernel is about to delete a function
       @param func: the func_t instance
       @return: 1-ok,<=0-do not delete
       """
       pass


    def is_call_insn(self, ea, func_name):
       """
       Is the instruction a "call"?

       @param ea: instruction address
       @return: 1-unknown, 0-no, 2-yes
       """
       pass


    def is_ret_insn(self, ea, func_name):
       """
       Is the instruction a "return"?

       @param ea: instruction address
       @param strict: - True: report only ret instructions
                        False: include instructions like "leave" which begins the function epilog
       @return: 1-unknown, 0-no, 2-yes
       """
       pass


    def assemble(self, ea, cs, ip, use32, line):
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
struct set_elf_reloc_t;
struct libfunc_t;

int idaapi IDP_Callback(void *ud, int notification_code, va_list va);
class IDP_Hooks
{
  friend int idaapi IDP_Callback(void *ud, int notification_code, va_list va);
  static int bool_to_cmdsize(bool in) { return in ? (1 + cmd.size) : 0; }
  static int bool_to_2or0(bool in) { return in ? 2 : 0; }
  static int cm_t_to_int(cm_t cm) { return int(cm); }
  static bool _handle_string_output(PyObject *o, char *buf, size_t bufsize)
  {
    bool is_str = o != NULL && PyString_Check(o);
    if ( is_str && buf != NULL )
      qstrncpy(buf, PyString_AS_STRING(o), bufsize);
    Py_XDECREF(o);
    return is_str;
  }
  static bool _handle_qstring_output(PyObject *o, qstring *buf)
  {
    bool is_str = o != NULL && PyString_Check(o);
    if ( is_str && buf != NULL )
      buf->append(PyString_AS_STRING(o));
    Py_XDECREF(o);
    return is_str;
  }
  static int handle_custom_mnem_output(PyObject *o, char *buf, size_t bufsize)
  {
    return _handle_string_output(o, buf, bufsize) ? 2 : 0;
  }
  static int handle_assemble_output(PyObject *o, ea_t /*ea*/, ea_t /*cs*/, ea_t /*ip*/, bool /*use32*/, const char */*line*/, uchar *bin)
  {
    int rc = 0;
    if ( o != NULL && PyString_Check(o) )
    {
      char *s;
      Py_ssize_t len = 0;
      if ( PyString_AsStringAndSize(o, &s, &len) != -1 )
      {
        if ( len > MAXSTR )
          len = MAXSTR;
        memcpy(bin, s, len);
      }
      rc = int(len);
    }
    Py_XDECREF(o);
    return rc;
  }
  static int handle_get_reg_name_output(PyObject *o, int /*reg*/, size_t /*width*/, char *buf, size_t bufsize, int /*reghi*/)
  {
    int rc = 0;
    if ( _handle_string_output(o, buf, bufsize) )
      rc = qstrlen(buf) + 2;
    return rc;
  }
  static int handle_decorate_name3_output(PyObject *o, qstring *outbuf, const char * /*name*/, bool /*mangle*/, int /*cc*/)
  {
    return _handle_qstring_output(o, outbuf) ? 2 : 0;
  }

public:
  virtual ~IDP_Hooks()
  {
    unhook();
  }

  bool hook()
  {
    return hook_to_notification_point(HT_IDP, IDP_Callback, this);
  }

  bool unhook()
  {
    return unhook_from_notification_point(HT_IDP, IDP_Callback, this);
  }
  // hookgenIDP:methods
virtual int init(const char * idp_modname) {qnotused(idp_modname); return 0;}
virtual int term() {return 0;}
virtual int newprc(int pnum) {qnotused(pnum); return 0;}
virtual int newasm(int asmnum) {qnotused(asmnum); return 0;}
virtual int newfile(char * fname) {qnotused(fname); return 0;}
virtual int oldfile(char * fname) {qnotused(fname); return 0;}
virtual int newbinary(char * filename, uint32 fileoff, ea_t basepara, ea_t binoff, uint32 nbytes) {qnotused(filename); qnotused(fileoff); qnotused(basepara); qnotused(binoff); qnotused(nbytes); return 0;}
virtual int endbinary(bool ok) {qnotused(ok); return 0;}
virtual int newseg(segment_t * seg) {qnotused(seg); return 0;}
virtual PyObject * assemble(ea_t ea, ea_t cs, ea_t ip, bool use32, const char * line) {qnotused(ea); qnotused(cs); qnotused(ip); qnotused(use32); qnotused(line); Py_RETURN_NONE;}
virtual int obsolete_makemicro(mblock_t * block) {qnotused(block); return 0;}
virtual int outlabel(ea_t ea, const char * colored_name) {qnotused(ea); qnotused(colored_name); return 0;}
virtual int rename(ea_t ea, const char * new_name) {qnotused(ea); qnotused(new_name); return 0;}
virtual int may_show_sreg(ea_t current_ea) {qnotused(current_ea); return 0;}
virtual int closebase() {return 0;}
virtual void load_idasgn(const char * short_sig_name) {qnotused(short_sig_name); }
virtual int coagulate(ea_t start_ea) {qnotused(start_ea); return 0;}
virtual void auto_empty() {}
virtual int auto_queue_empty(atype_t type) {qnotused(type); return 0;}
virtual void func_bounds(int * possible_return_code, func_t * pfn, ea_t max_func_end_ea) {qnotused(possible_return_code); qnotused(pfn); qnotused(max_func_end_ea); }
virtual int may_be_func(int state) {qnotused(state); return 0;}
virtual int is_sane_insn(int no_crefs) {qnotused(no_crefs); return 0;}
virtual int is_jump_func(func_t * pfn, ea_t * jump_target, ea_t * func_pointer) {qnotused(pfn); qnotused(jump_target); qnotused(func_pointer); return 0;}
virtual int gen_regvar_def(regvar_t * v) {qnotused(v); return 0;}
virtual int setsgr(ea_t startEA, ea_t endEA, int regnum, sel_t value, sel_t old_value, uchar tag) {qnotused(startEA); qnotused(endEA); qnotused(regnum); qnotused(value); qnotused(old_value); qnotused(tag); return 0;}
virtual int set_compiler() {return 0;}
virtual int is_basic_block_end(bool call_insn_stops_block) {qnotused(call_insn_stops_block); return 0;}
virtual int reglink() {return 0;}
virtual void get_vxd_name(int vxdnum, int funcnum, char * outbuf) {qnotused(vxdnum); qnotused(funcnum); qnotused(outbuf); }
virtual bool custom_ana() {return false;}
virtual bool custom_out() {return false;}
virtual bool custom_emu() {return false;}
virtual bool custom_outop(PyObject * op) {qnotused(op); return false;}
virtual PyObject * custom_mnem() {Py_RETURN_NONE;}
virtual int undefine(ea_t ea) {qnotused(ea); return 0;}
virtual int make_code(ea_t ea, asize_t size) {qnotused(ea); qnotused(size); return 0;}
virtual int make_data(ea_t ea, flags_t flags, tid_t tid, asize_t len) {qnotused(ea); qnotused(flags); qnotused(tid); qnotused(len); return 0;}
virtual int moving_segm(segment_t * seg, ea_t to, int flags) {qnotused(seg); qnotused(to); qnotused(flags); return 0;}
virtual void move_segm(ea_t from, segment_t * seg) {qnotused(from); qnotused(seg); }
virtual int is_call_insn(ea_t ea) {qnotused(ea); return 0;}
virtual int is_ret_insn(ea_t ea, bool strict) {qnotused(ea); qnotused(strict); return 0;}
virtual int get_stkvar_scale_factor() {return 0;}
virtual int create_flat_group(ea_t image_base, int bitness, sel_t dataseg_sel) {qnotused(image_base); qnotused(bitness); qnotused(dataseg_sel); return 0;}
virtual void kernel_config_loaded() {}
virtual int might_change_sp(ea_t ea) {qnotused(ea); return 0;}
virtual int is_alloca_probe(ea_t ea) {qnotused(ea); return 0;}
virtual int out_3byte(ea_t dataea, uint32 value, bool analyze_only) {qnotused(dataea); qnotused(value); qnotused(analyze_only); return 0;}
virtual PyObject * get_reg_name(int reg, size_t width, int reghi) {qnotused(reg); qnotused(width); qnotused(reghi); Py_RETURN_NONE;}
virtual void savebase() {}
virtual void gen_asm_or_lst(bool starting, FILE * fp, bool is_asm, int flags, gen_outline_t ** outline) {qnotused(starting); qnotused(fp); qnotused(is_asm); qnotused(flags); qnotused(outline); }
virtual int out_src_file_lnnum() {return 0;}
virtual int get_autocmt(char * buf, size_t bufsize) {qnotused(buf); qnotused(bufsize); return 0;}
virtual int is_insn_table_jump() {return 0;}
virtual void auto_empty_finally() {}
virtual int loader_finished(linput_t * li, uint16 neflags, const char * filetypename) {qnotused(li); qnotused(neflags); qnotused(filetypename); return 0;}
virtual int loader_elf_machine(linput_t * li, int machine_type, const char ** p_procname, proc_def ** p_pd, set_elf_reloc_t * set_reloc) {qnotused(li); qnotused(machine_type); qnotused(p_procname); qnotused(p_pd); qnotused(set_reloc); return 0;}
virtual int is_indirect_jump() {return 0;}
virtual int verify_noreturn(func_t * pfn) {qnotused(pfn); return 0;}
virtual int verify_sp(func_t * pfn) {qnotused(pfn); return 0;}
virtual void renamed(ea_t ea, const char * new_name, bool local_name) {qnotused(ea); qnotused(new_name); qnotused(local_name); }
virtual void add_func(func_t * pfn) {qnotused(pfn); }
virtual int del_func(func_t * pfn) {qnotused(pfn); return 0;}
virtual int set_func_start(func_t * pfn, ea_t new_start) {qnotused(pfn); qnotused(new_start); return 0;}
virtual int set_func_end(func_t * pfn, ea_t new_end) {qnotused(pfn); qnotused(new_end); return 0;}
virtual int treat_hindering_item(ea_t hindering_item_ea, flags_t new_item_flags, ea_t new_item_ea, asize_t new_item_length) {qnotused(hindering_item_ea); qnotused(new_item_flags); qnotused(new_item_ea); qnotused(new_item_length); return 0;}
virtual int str2reg(const char * regname) {qnotused(regname); return 0;}
virtual int create_switch_xrefs(ea_t jumpea, switch_info_ex_t * si) {qnotused(jumpea); qnotused(si); return 0;}
virtual int calc_switch_cases(ea_t insn_ea, switch_info_ex_t * si, casevec_t * casevec, eavec_t * targets) {qnotused(insn_ea); qnotused(si); qnotused(casevec); qnotused(targets); return 0;}
virtual void determined_main(ea_t main) {qnotused(main); }
virtual void preprocess_chart(qflow_chart_t * fc) {qnotused(fc); }
virtual int get_bg_color(ea_t ea, bgcolor_t color) {qnotused(ea); qnotused(color); return 0;}
virtual int validate_flirt_func(ea_t start_ea, const char * funcname) {qnotused(start_ea); qnotused(funcname); return 0;}
virtual int get_operand_string(int opnum, char * buf, size_t buflen) {qnotused(opnum); qnotused(buf); qnotused(buflen); return 0;}
virtual int add_cref(ea_t from, ea_t to, cref_t type) {qnotused(from); qnotused(to); qnotused(type); return 0;}
virtual int add_dref(ea_t from, ea_t to, dref_t type) {qnotused(from); qnotused(to); qnotused(type); return 0;}
virtual int del_cref(ea_t from, ea_t to, bool expand) {qnotused(from); qnotused(to); qnotused(expand); return 0;}
virtual int del_dref(ea_t from, ea_t to) {qnotused(from); qnotused(to); return 0;}
virtual int coagulate_dref(ea_t from, ea_t to, bool may_define, ea_t * code_ea) {qnotused(from); qnotused(to); qnotused(may_define); qnotused(code_ea); return 0;}
virtual int register_custom_fixup(const char * name) {qnotused(name); return 0;}
virtual int custom_refinfo(ea_t ea, int numop, ea_t * opval, const refinfo_t* ri, char * buf, size_t bufsize, ea_t * target, ea_t * fullvalue, ea_t from, int getn_flags) {qnotused(ea); qnotused(numop); qnotused(opval); qnotused(ri); qnotused(buf); qnotused(bufsize); qnotused(target); qnotused(fullvalue); qnotused(from); qnotused(getn_flags); return 0;}
virtual int set_proc_options(const char * options) {qnotused(options); return 0;}
virtual int adjust_libfunc_ea(const idasgn_t * sig, const libfunc_t * libfun, ea_t * ea) {qnotused(sig); qnotused(libfun); qnotused(ea); return 0;}
virtual void extlang_changed(int kind, const extlang_t * el) {qnotused(kind); qnotused(el); }
virtual int delay_slot_insn(ea_t * ea) {qnotused(ea); return 0;}
virtual int obsolete_get_operand_info() {return 0;}
virtual int get_jump_target(ea_t ea, int tid, processor_t::regval_getter_t getreg, const regval_t * regvalues, ea_t * target) {qnotused(ea); qnotused(tid); qnotused(getreg); qnotused(regvalues); qnotused(target); return 0;}
virtual int calc_step_over(ea_t ip, ea_t * target) {qnotused(ip); qnotused(target); return 0;}
virtual int get_macro_insn_head(ea_t ip, ea_t * head) {qnotused(ip); qnotused(head); return 0;}
virtual int get_dbr_opnum(ea_t ea, int * opnum) {qnotused(ea); qnotused(opnum); return 0;}
virtual int insn_reads_tbit(ea_t ea, processor_t::regval_getter_t getreg, const regval_t * regvalues) {qnotused(ea); qnotused(getreg); qnotused(regvalues); return 0;}
virtual int get_operand_info(ea_t ea, int n, int thread_id, processor_t::regval_getter_t getreg, const regval_t * regvalues, idd_opinfo_t * opinf) {qnotused(ea); qnotused(n); qnotused(thread_id); qnotused(getreg); qnotused(regvalues); qnotused(opinf); return 0;}
virtual int calc_next_eas(bool over, ea_t * res, int * nsubcalls) {qnotused(over); qnotused(res); qnotused(nsubcalls); return 0;}
virtual int clean_tbit(ea_t ea, processor_t::regval_getter_t getreg, const regval_t * regvalues) {qnotused(ea); qnotused(getreg); qnotused(regvalues); return 0;}
virtual int get_reg_info2(const char * regname, const char ** main_regname, bitrange_t * bitrange) {qnotused(regname); qnotused(main_regname); qnotused(bitrange); return 0;}
virtual void setup_til() {}
virtual int based_ptr(unsigned ptrt, const char ** ptrname) {qnotused(ptrt); qnotused(ptrname); return 0;}
virtual int max_ptr_size() {return 0;}
virtual int get_default_enum_size(cm_t cm) {qnotused(cm); return 0;}
virtual int calc_cdecl_purged_bytes2() {return 0;}
virtual int get_stkarg_offset2() {return 0;}
virtual int til_for_file() {return 0;}
virtual int equal_reglocs(argloc_t * a1, argloc_t * a2) {qnotused(a1); qnotused(a2); return 0;}
virtual PyObject * decorate_name3(const char * name, bool mangle, int cc) {qnotused(name); qnotused(mangle); qnotused(cc); Py_RETURN_NONE;}
virtual int calc_retloc3(const tinfo_t * rettype, cm_t cc, argloc_t * retloc) {qnotused(rettype); qnotused(cc); qnotused(retloc); return 0;}
virtual int calc_varglocs3(const func_type_data_t * ftd, regobjs_t * regs, relobj_t * stkargs, int nfixed) {qnotused(ftd); qnotused(regs); qnotused(stkargs); qnotused(nfixed); return 0;}
virtual int calc_arglocs3(func_type_data_t * fti) {qnotused(fti); return 0;}
virtual int use_stkarg_type3(ea_t ea, const funcarg_t * arg) {qnotused(ea); qnotused(arg); return 0;}
virtual int use_regarg_type3(int * idx, ea_t ea, const funcargvec_t * rargs) {qnotused(idx); qnotused(ea); qnotused(rargs); return 0;}
virtual int use_arg_types3(ea_t ea, func_type_data_t * fti, funcargvec_t * rargs) {qnotused(ea); qnotused(fti); qnotused(rargs); return 0;}
virtual int calc_purged_bytes3(int * p_purged_bytes, const func_type_data_t * fti) {qnotused(p_purged_bytes); qnotused(fti); return 0;}
virtual int shadow_args_size(int * shadow_args_size, func_t * pfn) {qnotused(shadow_args_size); qnotused(pfn); return 0;}
virtual int get_varcall_regs3(callregs_t * regs) {qnotused(regs); return 0;}
virtual int get_fastcall_regs3(callregs_t * regs) {qnotused(regs); return 0;}
virtual int get_thiscall_regs3(callregs_t * regs) {qnotused(regs); return 0;}
virtual int get_func_cvtarg_map(const func_type_data_t * fti, intvec_t * argnums) {qnotused(fti); qnotused(argnums); return 0;}
virtual int get_simd_types(const simd_info_t * simd_attrs, const argloc_t * argloc, simd_info_vec_t * out, bool create_tifs) {qnotused(simd_attrs); qnotused(argloc); qnotused(out); qnotused(create_tifs); return 0;}
virtual int loader() {return 0;}
};

enum areacb_type_t
{
  AREACB_TYPE_UNKNOWN,
  AREACB_TYPE_FUNC,
  AREACB_TYPE_SEGMENT,
  AREACB_TYPE_HIDDEN_AREA,
  AREACB_TYPE_SRAREA,
};
//</inline(py_idp)>

//-------------------------------------------------------------------------
//<code(py_idp)>
//-------------------------------------------------------------------------
int idaapi IDP_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;
  IDP_Hooks *proxy = (IDP_Hooks *)ud;
  int ret = 0;
  try
  {
    switch ( notification_code )
    {
      // hookgenIDP:notifications
case processor_t::init:
{
  const char * idp_modname = va_arg(va, const char *);
  ret = proxy->init(idp_modname);
}
break;

case processor_t::term:
{
  ret = proxy->term();
}
break;

case processor_t::newprc:
{
  int pnum = va_arg(va, int);
  ret = proxy->newprc(pnum);
}
break;

case processor_t::newasm:
{
  int asmnum = va_arg(va, int);
  ret = proxy->newasm(asmnum);
}
break;

case processor_t::newfile:
{
  char * fname = va_arg(va, char *);
  ret = proxy->newfile(fname);
}
break;

case processor_t::oldfile:
{
  char * fname = va_arg(va, char *);
  ret = proxy->oldfile(fname);
}
break;

case processor_t::newbinary:
{
  char * filename = va_arg(va, char *);
  uint32 fileoff = va_arg(va, uint32);
  ea_t basepara = va_arg(va, ea_t);
  ea_t binoff = va_arg(va, ea_t);
  uint32 nbytes = va_arg(va, uint32);
  ret = proxy->newbinary(filename, fileoff, basepara, binoff, nbytes);
}
break;

case processor_t::endbinary:
{
  bool ok = bool(va_arg(va, int));
  ret = proxy->endbinary(ok);
}
break;

case processor_t::newseg:
{
  segment_t * seg = va_arg(va, segment_t *);
  ret = proxy->newseg(seg);
}
break;

case processor_t::assemble:
{
  ea_t ea = va_arg(va, ea_t);
  ea_t cs = va_arg(va, ea_t);
  ea_t ip = va_arg(va, ea_t);
  bool use32 = bool(va_arg(va, int));
  const char * line = va_arg(va, const char *);
  uchar * bin = va_arg(va, uchar *);
  PyObject * _tmp = proxy->assemble(ea, cs, ip, use32, line);
  ret = IDP_Hooks::handle_assemble_output(_tmp, ea, cs, ip, use32, line, bin);
}
break;

case processor_t::obsolete_makemicro:
{
  mblock_t * block = va_arg(va, mblock_t *);
  ret = proxy->obsolete_makemicro(block);
}
break;

case processor_t::outlabel:
{
  ea_t ea = va_arg(va, ea_t);
  const char * colored_name = va_arg(va, const char *);
  ret = proxy->outlabel(ea, colored_name);
}
break;

case processor_t::rename:
{
  ea_t ea = va_arg(va, ea_t);
  const char * new_name = va_arg(va, const char *);
  int flags = va_arg(va, int);
  qnotused(flags);
  ret = proxy->rename(ea, new_name);
}
break;

case processor_t::may_show_sreg:
{
  ea_t current_ea = va_arg(va, ea_t);
  ret = proxy->may_show_sreg(current_ea);
}
break;

case processor_t::closebase:
{
  ret = proxy->closebase();
}
break;

case processor_t::load_idasgn:
{
  const char * short_sig_name = va_arg(va, const char *);
  proxy->load_idasgn(short_sig_name);
}
break;

case processor_t::coagulate:
{
  ea_t start_ea = va_arg(va, ea_t);
  ret = proxy->coagulate(start_ea);
}
break;

case processor_t::auto_empty:
{
  proxy->auto_empty();
}
break;

case processor_t::auto_queue_empty:
{
  atype_t type = va_arg(va, atype_t);
  ret = proxy->auto_queue_empty(type);
}
break;

case processor_t::func_bounds:
{
  int * possible_return_code = va_arg(va, int *);
  func_t * pfn = va_arg(va, func_t *);
  ea_t max_func_end_ea = va_arg(va, ea_t);
  proxy->func_bounds(possible_return_code, pfn, max_func_end_ea);
}
break;

case processor_t::may_be_func:
{
  int state = va_arg(va, int);
  ret = proxy->may_be_func(state);
}
break;

case processor_t::is_sane_insn:
{
  int no_crefs = va_arg(va, int);
  ret = proxy->is_sane_insn(no_crefs);
}
break;

case processor_t::is_jump_func:
{
  func_t * pfn = va_arg(va, func_t *);
  ea_t * jump_target = va_arg(va, ea_t *);
  ea_t * func_pointer = va_arg(va, ea_t *);
  ret = proxy->is_jump_func(pfn, jump_target, func_pointer);
}
break;

case processor_t::gen_regvar_def:
{
  regvar_t * v = va_arg(va, regvar_t *);
  ret = proxy->gen_regvar_def(v);
}
break;

case processor_t::setsgr:
{
  ea_t startEA = va_arg(va, ea_t);
  ea_t endEA = va_arg(va, ea_t);
  int regnum = va_arg(va, int);
  sel_t value = va_arg(va, sel_t);
  sel_t old_value = va_arg(va, sel_t);
  uchar tag = uchar(va_arg(va, int));
  ret = proxy->setsgr(startEA, endEA, regnum, value, old_value, tag);
}
break;

case processor_t::set_compiler:
{
  ret = proxy->set_compiler();
}
break;

case processor_t::is_basic_block_end:
{
  bool call_insn_stops_block = bool(va_arg(va, int));
  ret = proxy->is_basic_block_end(call_insn_stops_block);
}
break;

case processor_t::reglink:
{
  ret = proxy->reglink();
}
break;

case processor_t::get_vxd_name:
{
  int vxdnum = va_arg(va, int);
  int funcnum = va_arg(va, int);
  char * outbuf = va_arg(va, char *);
  proxy->get_vxd_name(vxdnum, funcnum, outbuf);
}
break;

case processor_t::custom_ana:
{
  bool _tmp = proxy->custom_ana();
  ret = IDP_Hooks::bool_to_cmdsize(_tmp);
}
break;

case processor_t::custom_out:
{
  bool _tmp = proxy->custom_out();
  ret = IDP_Hooks::bool_to_2or0(_tmp);
}
break;

case processor_t::custom_emu:
{
  bool _tmp = proxy->custom_emu();
  ret = IDP_Hooks::bool_to_2or0(_tmp);
}
break;

case processor_t::custom_outop:
{
  op_t * op = va_arg(va, op_t *);
  ref_t clinked_op = create_idaapi_linked_class_instance(S_PY_OP_T_CLSNAME, op);
  if ( clinked_op == NULL )
    break;
  bool _tmp = proxy->custom_outop(clinked_op.o);
  ret = IDP_Hooks::bool_to_2or0(_tmp);
}
break;

case processor_t::custom_mnem:
{
  char * buf = va_arg(va, char *);
  size_t bufsize = va_arg(va, size_t);
  PyObject * _tmp = proxy->custom_mnem();
  ret = IDP_Hooks::handle_custom_mnem_output(_tmp, buf, bufsize);
}
break;

case processor_t::undefine:
{
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->undefine(ea);
}
break;

case processor_t::make_code:
{
  ea_t ea = va_arg(va, ea_t);
  asize_t size = va_arg(va, asize_t);
  ret = proxy->make_code(ea, size);
}
break;

case processor_t::make_data:
{
  ea_t ea = va_arg(va, ea_t);
  flags_t flags = va_arg(va, flags_t);
  tid_t tid = va_arg(va, tid_t);
  asize_t len = va_arg(va, asize_t);
  ret = proxy->make_data(ea, flags, tid, len);
}
break;

case processor_t::moving_segm:
{
  segment_t * seg = va_arg(va, segment_t *);
  ea_t to = va_arg(va, ea_t);
  int flags = va_arg(va, int);
  ret = proxy->moving_segm(seg, to, flags);
}
break;

case processor_t::move_segm:
{
  ea_t from = va_arg(va, ea_t);
  segment_t * seg = va_arg(va, segment_t *);
  proxy->move_segm(from, seg);
}
break;

case processor_t::is_call_insn:
{
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->is_call_insn(ea);
}
break;

case processor_t::is_ret_insn:
{
  ea_t ea = va_arg(va, ea_t);
  bool strict = bool(va_arg(va, int));
  ret = proxy->is_ret_insn(ea, strict);
}
break;

case processor_t::get_stkvar_scale_factor:
{
  ret = proxy->get_stkvar_scale_factor();
}
break;

case processor_t::create_flat_group:
{
  ea_t image_base = va_arg(va, ea_t);
  int bitness = va_arg(va, int);
  sel_t dataseg_sel = va_arg(va, sel_t);
  ret = proxy->create_flat_group(image_base, bitness, dataseg_sel);
}
break;

case processor_t::kernel_config_loaded:
{
  proxy->kernel_config_loaded();
}
break;

case processor_t::might_change_sp:
{
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->might_change_sp(ea);
}
break;

case processor_t::is_alloca_probe:
{
  ea_t ea = va_arg(va, ea_t);
  ret = proxy->is_alloca_probe(ea);
}
break;

case processor_t::out_3byte:
{
  ea_t dataea = va_arg(va, ea_t);
  uint32 value = va_arg(va, uint32);
  bool analyze_only = bool(va_arg(va, int));
  ret = proxy->out_3byte(dataea, value, analyze_only);
}
break;

case processor_t::get_reg_name:
{
  int reg = va_arg(va, int);
  size_t width = va_arg(va, size_t);
  char * buf = va_arg(va, char *);
  size_t bufsize = va_arg(va, size_t);
  int reghi = va_arg(va, int);
  PyObject * _tmp = proxy->get_reg_name(reg, width, reghi);
  ret = IDP_Hooks::handle_get_reg_name_output(_tmp, reg, width, buf, bufsize, reghi);
}
break;

case processor_t::savebase:
{
  proxy->savebase();
}
break;

case processor_t::gen_asm_or_lst:
{
  bool starting = bool(va_arg(va, int));
  FILE * fp = va_arg(va, FILE *);
  bool is_asm = bool(va_arg(va, int));
  int flags = va_arg(va, int);
  gen_outline_t ** outline = va_arg(va, gen_outline_t **);
  proxy->gen_asm_or_lst(starting, fp, is_asm, flags, outline);
}
break;

case processor_t::out_src_file_lnnum:
{
  ret = proxy->out_src_file_lnnum();
}
break;

case processor_t::get_autocmt:
{
  char * buf = va_arg(va, char *);
  size_t bufsize = va_arg(va, size_t);
  ret = proxy->get_autocmt(buf, bufsize);
}
break;

case processor_t::is_insn_table_jump:
{
  ret = proxy->is_insn_table_jump();
}
break;

case processor_t::auto_empty_finally:
{
  proxy->auto_empty_finally();
}
break;

case processor_t::loader_finished:
{
  linput_t * li = va_arg(va, linput_t *);
  uint16 neflags = uint16(va_arg(va, int));
  const char * filetypename = va_arg(va, const char *);
  ret = proxy->loader_finished(li, neflags, filetypename);
}
break;

case processor_t::loader_elf_machine:
{
  linput_t * li = va_arg(va, linput_t *);
  int machine_type = va_arg(va, int);
  const char ** p_procname = va_arg(va, const char **);
  proc_def ** p_pd = va_arg(va, proc_def **);
  set_elf_reloc_t * set_reloc = va_arg(va, set_elf_reloc_t *);
  ret = proxy->loader_elf_machine(li, machine_type, p_procname, p_pd, set_reloc);
}
break;

case processor_t::is_indirect_jump:
{
  ret = proxy->is_indirect_jump();
}
break;

case processor_t::verify_noreturn:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->verify_noreturn(pfn);
}
break;

case processor_t::verify_sp:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->verify_sp(pfn);
}
break;

case processor_t::renamed:
{
  ea_t ea = va_arg(va, ea_t);
  const char * new_name = va_arg(va, const char *);
  bool local_name = bool(va_arg(va, int));
  proxy->renamed(ea, new_name, local_name);
}
break;

case processor_t::add_func:
{
  func_t * pfn = va_arg(va, func_t *);
  proxy->add_func(pfn);
}
break;

case processor_t::del_func:
{
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->del_func(pfn);
}
break;

case processor_t::set_func_start:
{
  func_t * pfn = va_arg(va, func_t *);
  ea_t new_start = va_arg(va, ea_t);
  ret = proxy->set_func_start(pfn, new_start);
}
break;

case processor_t::set_func_end:
{
  func_t * pfn = va_arg(va, func_t *);
  ea_t new_end = va_arg(va, ea_t);
  ret = proxy->set_func_end(pfn, new_end);
}
break;

case processor_t::treat_hindering_item:
{
  ea_t hindering_item_ea = va_arg(va, ea_t);
  flags_t new_item_flags = va_arg(va, flags_t);
  ea_t new_item_ea = va_arg(va, ea_t);
  asize_t new_item_length = va_arg(va, asize_t);
  ret = proxy->treat_hindering_item(hindering_item_ea, new_item_flags, new_item_ea, new_item_length);
}
break;

case processor_t::str2reg:
{
  const char * regname = va_arg(va, const char *);
  ret = proxy->str2reg(regname);
}
break;

case processor_t::create_switch_xrefs:
{
  ea_t jumpea = va_arg(va, ea_t);
  switch_info_ex_t * si = va_arg(va, switch_info_ex_t *);
  ret = proxy->create_switch_xrefs(jumpea, si);
}
break;

case processor_t::calc_switch_cases:
{
  ea_t insn_ea = va_arg(va, ea_t);
  switch_info_ex_t * si = va_arg(va, switch_info_ex_t *);
  casevec_t * casevec = va_arg(va, casevec_t *);
  eavec_t * targets = va_arg(va, eavec_t *);
  ret = proxy->calc_switch_cases(insn_ea, si, casevec, targets);
}
break;

case processor_t::determined_main:
{
  ea_t main = va_arg(va, ea_t);
  proxy->determined_main(main);
}
break;

case processor_t::preprocess_chart:
{
  qflow_chart_t * fc = va_arg(va, qflow_chart_t *);
  proxy->preprocess_chart(fc);
}
break;

case processor_t::get_bg_color:
{
  ea_t ea = va_arg(va, ea_t);
  bgcolor_t color = va_arg(va, bgcolor_t);
  ret = proxy->get_bg_color(ea, color);
}
break;

case processor_t::validate_flirt_func:
{
  ea_t start_ea = va_arg(va, ea_t);
  const char * funcname = va_arg(va, const char *);
  ret = proxy->validate_flirt_func(start_ea, funcname);
}
break;

case processor_t::get_operand_string:
{
  int opnum = va_arg(va, int);
  char * buf = va_arg(va, char *);
  size_t buflen = va_arg(va, size_t);
  ret = proxy->get_operand_string(opnum, buf, buflen);
}
break;

case processor_t::add_cref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  cref_t type = cref_t(va_arg(va, int));
  ret = proxy->add_cref(from, to, type);
}
break;

case processor_t::add_dref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  dref_t type = dref_t(va_arg(va, int));
  ret = proxy->add_dref(from, to, type);
}
break;

case processor_t::del_cref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  bool expand = bool(va_arg(va, int));
  ret = proxy->del_cref(from, to, expand);
}
break;

case processor_t::del_dref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  ret = proxy->del_dref(from, to);
}
break;

case processor_t::coagulate_dref:
{
  ea_t from = va_arg(va, ea_t);
  ea_t to = va_arg(va, ea_t);
  bool may_define = bool(va_arg(va, int));
  ea_t * code_ea = va_arg(va, ea_t *);
  ret = proxy->coagulate_dref(from, to, may_define, code_ea);
}
break;

case processor_t::register_custom_fixup:
{
  const char * name = va_arg(va, const char *);
  ret = proxy->register_custom_fixup(name);
}
break;

case processor_t::custom_refinfo:
{
  ea_t ea = va_arg(va, ea_t);
  int numop = va_arg(va, int);
  ea_t * opval = va_arg(va, ea_t *);
  const refinfo_t* ri = va_arg(va, const refinfo_t*);
  char * buf = va_arg(va, char *);
  size_t bufsize = va_arg(va, size_t);
  ea_t * target = va_arg(va, ea_t *);
  ea_t * fullvalue = va_arg(va, ea_t *);
  ea_t from = va_arg(va, ea_t);
  int getn_flags = va_arg(va, int);
  ret = proxy->custom_refinfo(ea, numop, opval, ri, buf, bufsize, target, fullvalue, from, getn_flags);
}
break;

case processor_t::set_proc_options:
{
  const char * options = va_arg(va, const char *);
  ret = proxy->set_proc_options(options);
}
break;

case processor_t::adjust_libfunc_ea:
{
  const idasgn_t * sig = va_arg(va, const idasgn_t *);
  const libfunc_t * libfun = va_arg(va, const libfunc_t *);
  ea_t * ea = va_arg(va, ea_t *);
  ret = proxy->adjust_libfunc_ea(sig, libfun, ea);
}
break;

case processor_t::extlang_changed:
{
  int kind = va_arg(va, int);
  const extlang_t * el = va_arg(va, const extlang_t *);
  proxy->extlang_changed(kind, el);
}
break;

case processor_t::delay_slot_insn:
{
  ea_t * ea = va_arg(va, ea_t *);
  ret = proxy->delay_slot_insn(ea);
}
break;

case processor_t::obsolete_get_operand_info:
{
  ret = proxy->obsolete_get_operand_info();
}
break;

case processor_t::get_jump_target:
{
  ea_t ea = va_arg(va, ea_t);
  int tid = va_arg(va, int);
  processor_t::regval_getter_t getreg = va_arg(va, processor_t::regval_getter_t);
  const regval_t * regvalues = va_arg(va, const regval_t *);
  ea_t * target = va_arg(va, ea_t *);
  ret = proxy->get_jump_target(ea, tid, getreg, regvalues, target);
}
break;

case processor_t::calc_step_over:
{
  ea_t ip = va_arg(va, ea_t);
  ea_t * target = va_arg(va, ea_t *);
  ret = proxy->calc_step_over(ip, target);
}
break;

case processor_t::get_macro_insn_head:
{
  ea_t ip = va_arg(va, ea_t);
  ea_t * head = va_arg(va, ea_t *);
  ret = proxy->get_macro_insn_head(ip, head);
}
break;

case processor_t::get_dbr_opnum:
{
  ea_t ea = va_arg(va, ea_t);
  int * opnum = va_arg(va, int *);
  ret = proxy->get_dbr_opnum(ea, opnum);
}
break;

case processor_t::insn_reads_tbit:
{
  ea_t ea = va_arg(va, ea_t);
  processor_t::regval_getter_t getreg = va_arg(va, processor_t::regval_getter_t);
  const regval_t * regvalues = va_arg(va, const regval_t *);
  ret = proxy->insn_reads_tbit(ea, getreg, regvalues);
}
break;

case processor_t::get_operand_info:
{
  ea_t ea = va_arg(va, ea_t);
  int n = va_arg(va, int);
  int thread_id = va_arg(va, int);
  processor_t::regval_getter_t getreg = va_arg(va, processor_t::regval_getter_t);
  const regval_t * regvalues = va_arg(va, const regval_t *);
  idd_opinfo_t * opinf = va_arg(va, idd_opinfo_t *);
  ret = proxy->get_operand_info(ea, n, thread_id, getreg, regvalues, opinf);
}
break;

case processor_t::calc_next_eas:
{
  bool over = bool(va_arg(va, int));
  ea_t * res = va_arg(va, ea_t *);
  int * nsubcalls = va_arg(va, int *);
  ret = proxy->calc_next_eas(over, res, nsubcalls);
}
break;

case processor_t::clean_tbit:
{
  ea_t ea = va_arg(va, ea_t);
  processor_t::regval_getter_t getreg = va_arg(va, processor_t::regval_getter_t);
  const regval_t * regvalues = va_arg(va, const regval_t *);
  ret = proxy->clean_tbit(ea, getreg, regvalues);
}
break;

case processor_t::get_reg_info2:
{
  const char * regname = va_arg(va, const char *);
  const char ** main_regname = va_arg(va, const char **);
  bitrange_t * bitrange = va_arg(va, bitrange_t *);
  ret = proxy->get_reg_info2(regname, main_regname, bitrange);
}
break;

case processor_t::setup_til:
{
  proxy->setup_til();
}
break;

case processor_t::based_ptr:
{
  unsigned ptrt = va_arg(va, unsigned);
  const char ** ptrname = va_arg(va, const char **);
  ret = proxy->based_ptr(ptrt, ptrname);
}
break;

case processor_t::max_ptr_size:
{
  ret = proxy->max_ptr_size();
}
break;

case processor_t::get_default_enum_size:
{
  cm_t cm = cm_t(va_arg(va, int));
  ret = proxy->get_default_enum_size(cm);
}
break;

case processor_t::calc_cdecl_purged_bytes2:
{
  ret = proxy->calc_cdecl_purged_bytes2();
}
break;

case processor_t::get_stkarg_offset2:
{
  ret = proxy->get_stkarg_offset2();
}
break;

case processor_t::til_for_file:
{
  ret = proxy->til_for_file();
}
break;

case processor_t::equal_reglocs:
{
  argloc_t * a1 = va_arg(va, argloc_t *);
  argloc_t * a2 = va_arg(va, argloc_t *);
  ret = proxy->equal_reglocs(a1, a2);
}
break;

case processor_t::decorate_name3:
{
  qstring * outbuf = va_arg(va, qstring *);
  const char * name = va_arg(va, const char *);
  bool mangle = bool(va_arg(va, int));
  cm_t cc = cm_t(va_arg(va, int));
  PyObject * _tmp = proxy->decorate_name3(name, mangle, IDP_Hooks::cm_t_to_int(cc));
  ret = IDP_Hooks::handle_decorate_name3_output(_tmp, outbuf, name, mangle, cc);
}
break;

case processor_t::calc_retloc3:
{
  const tinfo_t * rettype = va_arg(va, const tinfo_t *);
  cm_t cc = cm_t(va_arg(va, int));
  argloc_t * retloc = va_arg(va, argloc_t *);
  ret = proxy->calc_retloc3(rettype, cc, retloc);
}
break;

case processor_t::calc_varglocs3:
{
  const func_type_data_t * ftd = va_arg(va, const func_type_data_t *);
  regobjs_t * regs = va_arg(va, regobjs_t *);
  relobj_t * stkargs = va_arg(va, relobj_t *);
  int nfixed = va_arg(va, int);
  ret = proxy->calc_varglocs3(ftd, regs, stkargs, nfixed);
}
break;

case processor_t::calc_arglocs3:
{
  func_type_data_t * fti = va_arg(va, func_type_data_t *);
  ret = proxy->calc_arglocs3(fti);
}
break;

case processor_t::use_stkarg_type3:
{
  ea_t ea = va_arg(va, ea_t);
  const funcarg_t * arg = va_arg(va, const funcarg_t *);
  ret = proxy->use_stkarg_type3(ea, arg);
}
break;

case processor_t::use_regarg_type3:
{
  int * idx = va_arg(va, int *);
  ea_t ea = va_arg(va, ea_t);
  const funcargvec_t * rargs = va_arg(va, const funcargvec_t *);
  ret = proxy->use_regarg_type3(idx, ea, rargs);
}
break;

case processor_t::use_arg_types3:
{
  ea_t ea = va_arg(va, ea_t);
  func_type_data_t * fti = va_arg(va, func_type_data_t *);
  funcargvec_t * rargs = va_arg(va, funcargvec_t *);
  ret = proxy->use_arg_types3(ea, fti, rargs);
}
break;

case processor_t::calc_purged_bytes3:
{
  int * p_purged_bytes = va_arg(va, int *);
  const func_type_data_t * fti = va_arg(va, const func_type_data_t *);
  ret = proxy->calc_purged_bytes3(p_purged_bytes, fti);
}
break;

case processor_t::shadow_args_size:
{
  int * shadow_args_size = va_arg(va, int *);
  func_t * pfn = va_arg(va, func_t *);
  ret = proxy->shadow_args_size(shadow_args_size, pfn);
}
break;

case processor_t::get_varcall_regs3:
{
  callregs_t * regs = va_arg(va, callregs_t *);
  ret = proxy->get_varcall_regs3(regs);
}
break;

case processor_t::get_fastcall_regs3:
{
  callregs_t * regs = va_arg(va, callregs_t *);
  ret = proxy->get_fastcall_regs3(regs);
}
break;

case processor_t::get_thiscall_regs3:
{
  callregs_t * regs = va_arg(va, callregs_t *);
  ret = proxy->get_thiscall_regs3(regs);
}
break;

case processor_t::get_func_cvtarg_map:
{
  const func_type_data_t * fti = va_arg(va, const func_type_data_t *);
  intvec_t * argnums = va_arg(va, intvec_t *);
  ret = proxy->get_func_cvtarg_map(fti, argnums);
}
break;

case processor_t::get_simd_types:
{
  const simd_info_t * simd_attrs = va_arg(va, const simd_info_t *);
  const argloc_t * argloc = va_arg(va, const argloc_t *);
  simd_info_vec_t * out = va_arg(va, simd_info_vec_t *);
  bool create_tifs = bool(va_arg(va, int));
  ret = proxy->get_simd_types(simd_attrs, argloc, out, create_tifs);
}
break;

case processor_t::loader:
{
  ret = proxy->loader();
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
  for ( int i=dbg->registers_size - 1; i >= 0; i-- )
  {
    if ( strieq(name, dbg->registers(i).name) )
      return &regvals[i];
  }
  static regval_t rv;
  return &rv;
}

//-------------------------------------------------------------------------
//</code(py_idp)>
//-------------------------------------------------------------------------

#endif
