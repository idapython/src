// Ignore the following symbols
%ignore WorkReg;
%ignore AbstractRegister;
%ignore rginfo;
%ignore insn_t::get_canon_mnem;
%ignore insn_t::get_canon_feature;
%ignore insn_t::is_canon_insn;
%ignore bytes_t;
%ignore IDPOPT_STR;
%ignore IDPOPT_NUM;
%ignore IDPOPT_BIT;
%ignore IDPOPT_FLT;
%ignore IDPOPT_I64;
%ignore IDPOPT_OK;
%ignore IDPOPT_BADKEY;
%ignore IDPOPT_BADTYPE;
%ignore IDPOPT_BADVALUE;
%ignore set_options_t;
%ignore read_user_config_file;

%ignore s_preline;
%ignore ca_operation_t;
%ignore _chkarg_cmd;
%ignore ENUM_SIZE;

%ignore asm_t::checkarg_dispatch;
%ignore asm_t::func_header;
%ignore asm_t::func_footer;
%ignore asm_t::get_type_name;
%ignore instruc_t;
%ignore processor_t;
%ignore ph;
%ignore IDB_Callback;
%ignore IDP_Callback;
%ignore _py_getreg;
%ignore free_processor_module;
%ignore read_config_file;
%ignore cfg_compiler_changed;

%ignore gen_idb_event;

%include "idp.hpp"
%feature("director") IDB_Hooks;
%feature("director") IDP_Hooks;

%extend areacb_t {
  areacb_type_t get_type()
  {
    areacb_type_t t = AREACB_TYPE_UNKNOWN;
    if ( $self == &funcs )
      t = AREACB_TYPE_FUNC;
    else if ( $self == &segs )
      t = AREACB_TYPE_SEGMENT;
    else if ( $self == &hidden_areas )
      t = AREACB_TYPE_HIDDEN_AREA;
    return t;
  }
}

%inline %{

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
  if (ph.notify != NULL &&
    (inslen = ph.notify(ph.assemble, ea, cs, ip, use32, line, buf)) > 0)
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
  if (ph.notify != NULL)
  {
    inslen = ph.notify(ph.assemble, ea, cs, ip, use32, line, buf);
    if (inslen > 0)
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
              &opinf) != 0 )
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
int idaapi IDP_Callback(void *ud, int notification_code, va_list va);
class IDP_Hooks
{
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

  virtual bool custom_ana()
  {
    return false;
  }

  virtual bool custom_out()
  {
    return false;
  }

  virtual bool custom_emu()
  {
    return false;
  }

  virtual bool custom_outop(PyObject *py_op)
  {
    return false;
  }

  virtual PyObject *custom_mnem()
  {
    Py_RETURN_NONE;
  }

  virtual int is_sane_insn(int no_crefs)
  {
    return 0;
  }

  virtual int may_be_func(int state)
  {
    return 0;
  }

  virtual int closebase()
  {
    return 0;
  }

  virtual void savebase()
  {
  }

  virtual void auto_empty_finally()
  {
  }

  virtual int rename(ea_t ea, const char *new_name)
  {
    return 0;
  }

  virtual void renamed(ea_t ea, const char *new_name, bool local_name)
  {
  }

  virtual int undefine(ea_t ea)
  {
    return 0;
  }

  virtual int make_code(ea_t ea, asize_t size)
  {
    return 0;
  }

  virtual int make_data(ea_t ea, flags_t flags, tid_t tid, asize_t len)
  {
    return 0;
  }

  virtual void load_idasgn(const char *short_sig_name)
  {
  }

  virtual void auto_empty()
  {
  }

  virtual int auto_queue_empty(atype_t type)
  {
    return 1; // Keep the queue empty.
  }

  virtual void add_func(func_t *func)
  {
  }

  virtual int del_func(func_t *func)
  {
    return 0;
  }

  virtual int is_call_insn(ea_t /*ea*/)
  {
    return 0;
  }

  virtual int is_ret_insn(ea_t /*ea*/, bool /*strict*/)
  {
    return 0;
  }

  virtual PyObject *assemble(
      ea_t /*ea*/,
      ea_t /*cs*/,
      ea_t /*ip*/,
      bool /*use32*/,
      const char * /*line*/)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    Py_RETURN_NONE;
  }
};

enum areacb_type_t
{
  AREACB_TYPE_UNKNOWN,
  AREACB_TYPE_FUNC,
  AREACB_TYPE_SEGMENT,
  AREACB_TYPE_HIDDEN_AREA,
  AREACB_TYPE_SRAREA,
};

//---------------------------------------------------------------------------
// IDB hooks
//---------------------------------------------------------------------------
int idaapi IDB_Callback(void *ud, int notification_code, va_list va);
class IDB_Hooks
{
public:
  virtual ~IDB_Hooks() { unhook(); };

  bool hook()
  {
    return hook_to_notification_point(HT_IDB, IDB_Callback, this);
  }
  bool unhook()
  {
    return unhook_from_notification_point(HT_IDB, IDB_Callback, this);
  }
  // Hook functions to override in Python
  virtual int byte_patched(ea_t /*ea*/) { return 0; }
  virtual int cmt_changed(ea_t, bool /*repeatable_cmt*/) { return 0; }
  virtual int area_cmt_changed(areacb_t * /*areas*/, area_t * /*area*/, const char * /*cmt*/, bool /*repeatable*/) { return 0; }
  virtual int ti_changed(ea_t /*ea*/, const type_t * /*type*/, const p_list * /*fnames*/) { return 0; }
  virtual int op_ti_changed(ea_t /*ea*/, int /*n*/, const type_t * /*type*/, const p_list * /*fnames*/) { return 0; }
  virtual int op_type_changed(ea_t /*ea*/, int /*n*/) { return 0; }
  virtual int enum_created(enum_t /*id*/) { return 0; }
  virtual int enum_deleted(enum_t /*id*/) { return 0; }
  virtual int enum_bf_changed(enum_t /*id*/) { return 0; }
  virtual int enum_renamed(enum_t /*id*/) { return 0; }
  virtual int enum_cmt_changed(enum_t /*id*/) { return 0; }
  virtual int enum_member_created(enum_t /*id*/, const_t cid) { return 0; }
  virtual int enum_member_deleted(enum_t /*id*/, const_t cid) { return 0; }
  virtual int struc_created(tid_t /*struc_id*/) { return 0; }
  virtual int struc_deleted(tid_t /*struc_id*/) { return 0; }
  virtual int struc_renamed(struc_t * /*sptr*/) { return 0; }
  virtual int struc_expanded(struc_t * /*sptr*/) { return 0; }
  virtual int struc_cmt_changed(tid_t /*struc_id*/) { return 0; }
  virtual int struc_member_created(struc_t * /*sptr*/, member_t * /*mptr*/) { return 0; }
  virtual int struc_member_deleted(struc_t * /*sptr*/, tid_t /*member_id*/, ea_t /*offset*/) { return 0; }
  virtual int struc_member_renamed(struc_t * /*sptr*/, member_t * /*mptr*/) { return 0; }
  virtual int struc_member_changed(struc_t * /*sptr*/, member_t * /*mptr*/) { return 0; }
  virtual int thunk_func_created(func_t * /*pfn*/) { return 0; }
  virtual int func_tail_appended(func_t * /*pfn*/, func_t * /*tail*/) { return 0; }
  virtual int func_tail_removed(func_t * /*pfn*/, ea_t /*tail_ea*/) { return 0; }
  virtual int tail_owner_changed(func_t * /*tail*/, ea_t /*owner_func*/) { return 0; }
  virtual int func_noret_changed(func_t * /*pfn*/) { return 0; }
  virtual int segm_added(segment_t * /*s*/) { return 0; }
  virtual int segm_deleted(ea_t /*startEA*/) { return 0; }
  virtual int segm_start_changed(segment_t * /*s*/) { return 0; }
  virtual int segm_end_changed(segment_t * /*s*/) { return 0; }
  virtual int segm_moved(ea_t /*from*/, ea_t /*to*/, asize_t /*size*/) { return 0; }
};

//</inline(py_idp)>
%}

%{
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
    case processor_t::custom_ana:
      ret = proxy->custom_ana() ? 1 + cmd.size : 0;
      break;

    case processor_t::custom_out:
      ret = proxy->custom_out() ? 2 : 0;
      break;

    case processor_t::custom_emu:
      ret = proxy->custom_emu() ? 2 : 0;
      break;

    case processor_t::custom_outop:
      {
        op_t *op = va_arg(va, op_t *);
        ref_t py_obj(create_idaapi_linked_class_instance(S_PY_OP_T_CLSNAME, op));
        if ( py_obj == NULL )
          break;
        ret = proxy->custom_outop(py_obj.o) ? 2 : 0;
        break;
      }

    case processor_t::custom_mnem:
      {
        PYW_GIL_CHECK_LOCKED_SCOPE();
        PyObject *py_ret = proxy->custom_mnem();
        if ( py_ret != NULL && PyString_Check(py_ret) )
        {
          char *outbuffer = va_arg(va, char *);
          size_t bufsize  = va_arg(va, size_t);

          qstrncpy(outbuffer, PyString_AS_STRING(py_ret), bufsize);
          ret = 2;
        }
        else
        {
          ret = 0;
        }
        Py_XDECREF(py_ret);
        break;
      }

    case processor_t::is_sane_insn:
      {
        int no_crefs = va_arg(va, int);
        ret = proxy->is_sane_insn(no_crefs);
        break;
      }

    case processor_t::may_be_func:
      {
        int state = va_arg(va, int);
        ret = proxy->may_be_func(state);
        break;
      }

    case processor_t::closebase:
      {
        proxy->closebase();
        break;
      }

    case processor_t::savebase:
      {
        proxy->savebase();
        break;
      }

    case processor_t::auto_empty_finally:
      {
        proxy->auto_empty_finally();
        break;
      }

    case processor_t::rename:
      {
        ea_t ea = va_arg(va, ea_t);
        const char *new_name = va_arg(va, const char *);
        ret = proxy->rename(ea, new_name);
        break;
      }

    case processor_t::renamed:
      {
        ea_t ea = va_arg(va, ea_t);
        const char *new_name = va_arg(va, const char *);
        bool local_name = va_argi(va, bool);
        proxy->renamed(ea, new_name, local_name);
        break;
      }

    case processor_t::undefine:
      {
        ea_t ea = va_arg(va, ea_t);
        ret = proxy->undefine(ea);
        break;
      }

    case processor_t::make_code:
      {
        ea_t ea = va_arg(va, ea_t);
        asize_t size = va_arg(va, asize_t);
        ret = proxy->make_code(ea, size);
        break;
      }

    case processor_t::make_data:
      {
        ea_t ea = va_arg(va, ea_t);
        flags_t flags = va_arg(va, flags_t);
        tid_t tid = va_arg(va, tid_t);
        asize_t len = va_arg(va, asize_t);
        ret = proxy->make_data(ea, flags, tid, len);
        break;
      }

    case processor_t::load_idasgn:
      {
        const char *short_sig_name = va_arg(va, const char *);
        proxy->load_idasgn(short_sig_name);
        break;
      }

    case processor_t::auto_empty:
      {
        proxy->auto_empty();
        break;
      }

    case processor_t::auto_queue_empty:
      {
        atype_t type = va_arg(va, atype_t);
        ret = proxy->auto_queue_empty(type);
        break;
      }

    case processor_t::add_func:
      {
        func_t *func = va_arg(va, func_t *);
        proxy->add_func(func);
        break;
      }

    case processor_t::del_func:
      {
        func_t *func = va_arg(va, func_t *);
        ret = proxy->del_func(func);
        break;
      }

    case processor_t::is_call_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        ret = proxy->is_call_insn(ea);
        break;
      }

    case processor_t::is_ret_insn:
      {
        ea_t ea = va_arg(va, ea_t);
        bool strict = va_argi(va, bool);
        ret = proxy->is_ret_insn(ea, strict);
        break;
      }

    case processor_t::assemble:
      {
        ea_t ea     = va_arg(va, ea_t);
        ea_t cs     = va_arg(va, ea_t);
        ea_t ip     = va_arg(va, ea_t);
        bool use32  = va_argi(va, bool);
        const char *line = va_arg(va, const char *);
        // Extract user buffer (we hardcode the MAXSTR size limit)
        uchar *bin = va_arg(va, uchar *);
        // Call python
        PYW_GIL_CHECK_LOCKED_SCOPE();
        PyObject *py_buffer = proxy->assemble(ea, cs, ip, use32, line);
        if ( py_buffer != NULL && PyString_Check(py_buffer) )
        {
          char *s;
          Py_ssize_t len;
          if ( PyString_AsStringAndSize(py_buffer, &s, &len) != -1 )
          {
            if ( len > MAXSTR )
              len = MAXSTR;
            memcpy(bin, s, len);
            ret = len;
          }
        }
        // ret = 0 otherwise
        Py_XDECREF(py_buffer);
        break;
      }
      //      validate_flirt_func,    // flirt has recognized a library function
      //      // this callback can be used by a plugin or proc module
      //      // to intercept it and validate such a function
      //      // args: ea_t start_ea
      //      //       const char *funcname
      //      // returns: -1-do not create a function,
      //      //           1-function is validated
      //      // the idp module is allowed to modify 'cmd'
      //      set_func_start,         // Function chunk start address will be changed
      //      // args: func_t *pfn
      //      //       ea_t new_start
      //      // Returns: 1-ok,<=0-do not change
      //      set_func_end,           // Function chunk end address will be changed
      //      // args: func_t *pfn
      //      //       ea_t new_end
      //      // Returns: 1-ok,<=0-do not change
      //    outlabel,               // The kernel is going to generate an instruction
      //      // label line or a function header
      //      // args:
      //      //   ea_t ea -
      //      //   const char *colored_name -
      //      // If returns value <=0, then the kernel should
      //      // not generate the label
      //      may_show_sreg,          // The kernel wants to display the segment registers
      //      // in the messages window.
      //      // arg - ea_t current_ea
      //      // if this function returns 0
      //      // then the kernel will not show
      //      // the segment registers.
      //      // (assuming that the module have done it)
      //      coagulate,              // Try to define some unexplored bytes
      //      // This notification will be called if the
      //      // kernel tried all possibilities and could
      //      // not find anything more useful than to
      //      // convert to array of bytes.
      //      // The module can help the kernel and convert
      //      // the bytes into something more useful.
      //      // arg:
      //      //      ea_t start_ea
      //      // returns: number of converted bytes + 1
      //      auto_empty,             // Info: all analysis queues are empty
      //      // args: none
      //      // returns: none
      //      // This callback is called once when the
      //      // initial analysis is finished. If the queue is
      //      // not empty upon the return from this callback,
      //      // it will be called later again.
      //      // See also auto_empty_finally.
      //      auto_queue_empty,       // One analysis queue is empty
      //      // args: atype_t type
      //      // returns: 1-yes, keep the queue empty
      //      //        <=0-no, the queue is not empty anymore
      //      // This callback can be called many times, so
      //      // only the autoMark() functions can be used from it
      //      // (other functions may work but it is not tested)
      //      func_bounds,            // find_func_bounds() finished its work
      //      // The module may fine tune the function bounds
      //      // args: int *possible_return_code
      //      //       func_t *pfn
      //      //       ea_t max_func_end_ea (from the kernel's point of view)
      //      // returns: none
      //      is_jump_func,           // is the function a trivial "jump" function?
      //      // args:  func_t *pfn
      //      //        ea_t *jump_target
      //      //        ea_t *func_pointer
      //      // returns: 0-no, 1-don't know, 2-yes, see jump_target
      //      // and func_pointer
      //      gen_regvar_def,         // generate register variable definition line
      //      // args:  regvar_t *v
      //      // returns: 0-ok
      //      setsgr,                 // The kernel has changed a segment register value
      //      // args:  ea_t startEA
      //      //        ea_t endEA
      //      //        int regnum
      //      //        sel_t value
      //      //        sel_t old_value
      //      //        uchar tag (SR_... values)
      //      // returns: 1-ok, 0-error
      //      set_compiler,           // The kernel has changed the compiler information
      //      // (inf.cc structure)
      //      is_basic_block_end,     // Is the current instruction end of a basic block?
      //      // This function should be defined for processors
      //      // with delayed jump slots. The current instruction
      //      // is stored in 'cmd'
      //      // args:  bool call_insn_stops_block
      //      // returns: 1-unknown, 0-no, 2-yes
      //      reglink,                // IBM PC only, ignore it
      //      get_vxd_name,           // IBM PC only, ignore it
      //      // Get Vxd function name
      //      // args: int vxdnum
      //      //       int funcnum
      //      //       char *outbuf
      //      // returns: nothing
      //
      //
      //      moving_segm,            // May the kernel move the segment?
      //      // args: segment_t - segment to move
      //      //       ea_t to   - new segment start address
      //      // returns: 1-yes, <=0-the kernel should stop
      //      move_segm,              // A segment is moved
      //      // Fix processor dependent address sensitive information
      //      // args: ea_t from  - old segment address
      //      //       segment_t* - moved segment
      //      // returns: nothing
      //
      //
      //      get_stkvar_scale_factor,// Should stack variable references be multiplied by
      //      // a coefficient before being used in the stack frame?
      //      // Currently used by TMS320C55 because the references into
      //      // the stack should be multiplied by 2
      //      // Returns: scaling factor
      //      // Note: PR_SCALE_STKVARS should be set to use this callback
      //
      //      create_flat_group,      // Create special segment representing the flat group
      //      // (to use for PC mainly)
      //      // args - ea_t image_base, int bitness, sel_t dataseg_sel
      //
      //      kernel_config_loaded,   // This callback is called when ida.cfg is parsed
      //      // args - none, returns - nothing
      //
      //      might_change_sp,        // Does the instruction at 'ea' modify the stack pointer?
      //      // args: ea_t ea
      //      // returns: 1-yes, 0-false
      //      // (not used yet)
      //
      //      is_alloca_probe,        // Does the function at 'ea' behave as __alloca_probe?
      //      // args: ea_t ea
      //      // returns: 2-yes, 1-false
      //
      //      out_3byte,              // Generate text representation of 3byte data
      //      // init_out_buffer() is called before this function
      //      // and all Out... function can be used.
      //      // uFlag contains the flags.
      //      // This callback might be implemented by the processor
      //      // module to generate custom representation of 3byte data.
      //      // args:
      //      // ea_t dataea - address of the data item
      //      // uint32 value - value to output
      //      // bool analyze_only - only create xrefs if necessary
      //      //              do not generate text representation
      //      // returns: 2-yes, 1-false
      //
      //      get_reg_name,           // Generate text representation of a register
      //      // int reg        - internal register number as defined in the processor module
      //      // size_t width   - register width in bytes
      //      // char *buf      - output buffer
      //      // size_t bufsize - size of output buffer
      //      // int reghi      - if not -1 then this function will return the register pair
      //      // returns: -1 if error, strlen(buf)+2 otherwise
      //      // Most processor modules do not need to implement this callback
      //      // It is useful only if ph.regNames[reg] does not provide
      //      // the correct register names
      //      // save its local data
      //      out_src_file_lnnum,     // Callback: generate analog of
      //      //   #line "file.c" 123
      //      // directive.
      //      // const char *file - source file (may be NULL)
      //      // size_t lnnum     - line number
      //      // returns: 2-directive has been generated
      //      get_autocmt,            // Callback: get dynamic auto comment
      //      // Will be called if the autocomments are enabled
      //      // and the comment retrieved from ida.int starts with
      //      // '$!'. 'cmd' is contains valid info.
      //      // char *buf  - output buffer
      //      // size_t bufsize - output buffer size
      //      // returns: 2-new comment has been generated
      //      //          1-callback has not been handled
      //      //            the buffer must not be changed in this case
      //      is_insn_table_jump,     // Callback: determine if instruction is a table jump or call
      //      // If CF_JUMP bit can not describe all kinds of table
      //      // jumps, please define this callback.
      //      // It will be called for insns with CF_JUMP bit set.
      //      // input: cmd structure contains the current instruction
      //      // returns: 1-yes, 0-no
      //      auto_empty_finally,     // Info: all analysis queues are empty definitively
      //      // args: none
      //      // returns: none
      //      // This callback is called only once.
      //      // See also auto_empty.
      //      loader_finished,        // Event: external file loader finished its work
      //      // linput_t *li
      //      // uint16 neflags
      //      // const char *filetypename
      //      // Use this event to augment the existing loader functionality
      //      loader_elf_machine,     // Event: ELF loader machine type checkpoint
      //      // linput_t *li
      //      // int machine_type
      //      // const char **p_procname
      //      // proc_def **p_pd (see ldr\elf.h)
      //      // set_elf_reloc_t *set_reloc
      //      // A plugin check the machine_type. If it is the desired one,
      //      // the the plugin fills p_procname with the processor name.
      //      // p_pd is used to handle relocations, otherwise can be left untouched
      //      // set_reloc can be later used by the plugin to specify relocations
      //      // returns: e_machine value (if it is different from the
      //      // original e_machine value, procname and p_pd will be ignored
      //      // and the new value will be used)
      //      // This event occurs for each loaded ELF file
      //      is_indirect_jump,       // Callback: determine if instruction is an indrect jump
      //      // If CF_JUMP bit can not describe all jump types
      //      // jumps, please define this callback.
      //      // input: cmd structure contains the current instruction
      //      // returns: 1-use CF_JUMP, 2-no, 3-yes
      //      verify_noreturn,        // The kernel wants to set 'noreturn' flags for a function
      //      // func_t *pfn
      //      // Returns: 1-ok, any other value-do not set 'noreturn' flag
      //      verify_sp,              // All function instructions have been analyzed
      //      // Now the processor module can analyze the stack pointer
      //      // for the whole function
      //      // input: func_t *pfn
      //      // Returns: 1-ok, 0-bad stack pointer
      //      treat_hindering_item,   // An item hinders creation of another item
      //      // args: ea_t hindering_item_ea
      //      //       flags_t new_item_flags (0 for code)
      //      //       ea_t new_item_ea
      //      //       asize_t new_item_length
      //      // Returns: 1-no reaction, <=0-the kernel may delete the hindering item
      //      str2reg,                // Convert a register name to a register number
      //      // args: const char *regname
      //      // Returns: register number + 2
      //      // The register number is the register index in the regNames array
      //      // Most processor modules do not need to implement this callback
      //      // It is useful only if ph.regNames[reg] does not provide
      //      // the correct register names
      //      create_switch_xrefs,    // Create xrefs for a custom jump table
      //      // in: ea_t jumpea;        - address of the jump insn
      //      //     switch_info_ex_t *; - switch information
      //      // returns: must return 2
      //      calc_switch_cases,      // Calculate case values and targets for a custom jump table
      //      // in:  ea_t insn_ea - address of the 'indirect jump' instruction
      //      //      switch_info_ex_t *si      - switch information
      //      //      casevec_t *casevec - vector of case values...
      //      //      evec_t *targets - ...and corresponding target addresses
      //      // casevec and targets may be NULL
      //      // returns: 2-ok, 1-failed
      //      determined_main,        // The main() function has been determined
      //      // in:  ea_t main - address of the main() function
      //      // returns: none
      //      preprocess_chart,       // gui has retrieved a function flow chart
      //      // in: qflow_chart_t *fc
      //      // returns: none
      //      // Plugins may modify the flow chart in this callback
      //      get_bg_color,           // Get item background color
      //      // in: ea_t ea, bgcolor_t *color
      //      // Returns: 1-not implemented, 2-color set
      //      // Plugins can hook this callback to color disassembly lines
      //      // dynamically
      //      get_operand_string,     // Request text string for operand (cli, java, ...)
      //      // args: int opnum
      //      //       char *buf
      //      //       size_t buflen
      //      // (cmd structure must contain info for the desired insn)
      //      // opnum is the operand number; -1 means any string operand
      //      // returns: 1 - no string (or empty string)
      //      //         >1 - original string length with terminating zero
      //
      //      // the following 5 events are very low level
      //      // take care of possible recursion
      //      add_cref,               // a code reference is being created
      //      // args: ea_t from, ea_t to, cref_t type
      //      // returns: <0 - cancel cref creation
      //      add_dref,               // a data reference is being created
      //      // args: ea_t from, ea_t to, dref_t type
      //      // returns: <0 - cancel dref creation
      //      del_cref,               // a code reference is being deleted
      //      // args: ea_t from, ea_t to, bool expand
      //      // returns: <0 - cancel cref deletion
      //      del_dref,               // a data reference is being deleted
      //      // args: ea_t from, ea_t to
      //      // returns: <0 - cancel dref deletion
      //      coagulate_dref,         // data reference is being analyzed
      //      // args: ea_t from, ea_t to, bool may_define, ea_t *code_ea
      //      // plugin may correct code_ea (e.g. for thumb mode refs, we clear the last bit)
      //      // returns: <0 - cancel dref analysis
      //      custom_fixup,           // mutipurpose notification for FIXUP_CUSTOM
      //      // args: cust_fix oper, ea_t ea, const fixup_data_t*, ... (see cust_fix)
      //      // returns: 1 - no accepted (fixup ignored by ida)
      //      //         >1 - accepted (see cust_fix)
      //      off_preproc,            // called from get_offset_expr, when refinfo_t
      //      // contain flag REFINFO_PREPROC. Normally this
      //      // notification used in a combination with custom_fixup
      //      // args: ea_t ea, int numop, ea_t* opval, const refinfo_t* ri,
      //      //       char* buf, size_t bufsize, ea_t* target,
      //      // ea_t* fullvalue, ea_t from, int getn_flags
      //      // returns: 2 - buf filled as simple expression
      //      //          3 - buf filled as complex expression
      //      //          4 - apply standard processing (with - possible - changed values)
      //      //     others - can't convert to offset expression
      //
      //      set_proc_options,       // called if the user specified an option string in the command line:
      //      //  -p<processor name>:<options>
      //      // can be used for e.g. setting a processor subtype
      //      // also called if option string is passed to set_processor_type()
      //      // and IDC's SetProcessorType()
      //      // args: const char * options
      //      // returns: <0 - bad option string
      //
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

//---------------------------------------------------------------------------
int idaapi IDB_Callback(void *ud, int notification_code, va_list va)
{
  // This hook gets called from the kernel. Ensure we hold the GIL.
  PYW_GIL_GET;

  class IDB_Hooks *proxy = (class IDB_Hooks *)ud;
  ea_t ea, ea2;
  bool repeatable_cmt;
  type_t *type;
  p_list *fnames;
  int n;
  enum_t id;
  const_t cid;
  tid_t struc_id;
  struc_t *sptr;
  member_t *mptr;
  tid_t member_id;
  func_t *pfn;
  func_t *tail;
  segment_t *seg;
  asize_t size;

  try {
    switch (notification_code)
    {
      case idb_event::byte_patched:
        ea = va_arg(va, ea_t);
        return proxy->byte_patched(ea);

      case idb_event::cmt_changed:
        ea = va_arg(va, ea_t);
        repeatable_cmt = va_arg(va, int);
        return proxy->cmt_changed(ea, repeatable_cmt);

      case idb_event::area_cmt_changed:
        {
          areacb_t *cb = va_arg(va, areacb_t*);
          area_t *area = va_arg(va, area_t*);
          const char *cmt = va_arg(va, char*);
          repeatable_cmt = va_arg(va, int);
          return proxy->area_cmt_changed(cb, area, cmt, repeatable_cmt);
        }

      case idb_event::ti_changed:
        ea = va_arg(va, ea_t);
        type = va_arg(va, type_t *);
        fnames = va_arg(va, p_list *);
        return proxy->ti_changed(ea, type, fnames);

      case idb_event::op_ti_changed:
        ea = va_arg(va, ea_t);
        n = va_arg(va, int);
        type = va_arg(va, type_t *);
        fnames = va_arg(va, p_list *);
        return proxy->op_ti_changed(ea, n, type, fnames);

      case idb_event::op_type_changed:
        ea = va_arg(va, ea_t);
        n = va_arg(va, int);
        return proxy->op_type_changed(ea, n);

      case idb_event::enum_created:
        id = va_arg(va, enum_t);
        return proxy->enum_created(id);

      case idb_event::enum_deleted:
        id = va_arg(va, enum_t);
        return proxy->enum_deleted(id);

      case idb_event::enum_bf_changed:
        id = va_arg(va, enum_t);
        return proxy->enum_bf_changed(id);

      case idb_event::enum_cmt_changed:
        id = va_arg(va, enum_t);
        return proxy->enum_cmt_changed(id);

#ifdef NO_OBSOLETE_FUNCS
      case idb_event::enum_member_created:
#else
      case idb_event::enum_const_created:
#endif
        id = va_arg(va, enum_t);
        cid = va_arg(va, const_t);
        return proxy->enum_member_created(id, cid);

#ifdef NO_OBSOLETE_FUNCS
      case idb_event::enum_member_deleted:
#else
      case idb_event::enum_const_deleted:
#endif
        id = va_arg(va, enum_t);
        cid = va_arg(va, const_t);
        return proxy->enum_member_deleted(id, cid);

      case idb_event::struc_created:
        struc_id = va_arg(va, tid_t);
        return proxy->struc_created(struc_id);

      case idb_event::struc_deleted:
        struc_id = va_arg(va, tid_t);
        return proxy->struc_deleted(struc_id);

      case idb_event::struc_renamed:
        sptr = va_arg(va, struc_t *);
        return proxy->struc_renamed(sptr);

      case idb_event::struc_expanded:
        sptr = va_arg(va, struc_t *);
        return proxy->struc_expanded(sptr);

      case idb_event::struc_cmt_changed:
        struc_id = va_arg(va, tid_t);
        return proxy->struc_cmt_changed(struc_id);

      case idb_event::struc_member_created:
        sptr = va_arg(va, struc_t *);
        mptr = va_arg(va, member_t *);
        return proxy->struc_member_created(sptr, mptr);

      case idb_event::struc_member_deleted:
        sptr = va_arg(va, struc_t *);
        member_id = va_arg(va, tid_t);
        ea        = va_arg(va, ea_t);
        return proxy->struc_member_deleted(sptr, member_id, ea);

      case idb_event::struc_member_renamed:
        sptr = va_arg(va, struc_t *);
        mptr = va_arg(va, member_t *);
        return proxy->struc_member_renamed(sptr, mptr);

      case idb_event::struc_member_changed:
        sptr = va_arg(va, struc_t *);
        mptr = va_arg(va, member_t *);
        return proxy->struc_member_changed(sptr, mptr);

      case idb_event::thunk_func_created:
        pfn = va_arg(va, func_t *);
        return proxy->thunk_func_created(pfn);

      case idb_event::func_tail_appended:
        pfn = va_arg(va, func_t *);
        tail = va_arg(va, func_t *);
        return proxy->func_tail_appended(pfn, tail);

      case idb_event::func_tail_removed:
        pfn = va_arg(va, func_t *);
        ea = va_arg(va, ea_t);
        return proxy->func_tail_removed(pfn, ea);

      case idb_event::tail_owner_changed:
        tail = va_arg(va, func_t *);
        ea = va_arg(va, ea_t);
        return proxy->tail_owner_changed(tail, ea);

      case idb_event::func_noret_changed:
        pfn = va_arg(va, func_t *);
        return proxy->func_noret_changed(pfn);

      case idb_event::segm_added:
        seg = va_arg(va, segment_t *);
        return proxy->segm_added(seg);

      case idb_event::segm_deleted:
        ea = va_arg(va, ea_t);
        return proxy->segm_deleted(ea);

      case idb_event::segm_start_changed:
        seg = va_arg(va, segment_t *);
        return proxy->segm_start_changed(seg);

      case idb_event::segm_end_changed:
        seg = va_arg(va, segment_t *);
        return proxy->segm_end_changed(seg);

      case idb_event::segm_moved:
        ea = va_arg(va, ea_t);
        ea2 = va_arg(va, ea_t);
        size = va_arg(va, asize_t);
        return proxy->segm_moved(ea, ea2, size);
    }
  }
  catch (Swig::DirectorException &e)
  {
    msg("Exception in IDB Hook function: %s\n", e.getMessage());
    PYW_GIL_CHECK_LOCKED_SCOPE();
    if (PyErr_Occurred())
      PyErr_Print();
  }
  return 0;
}

//-------------------------------------------------------------------------
static const regval_t *idaapi _py_getreg(
    const char *name,
    const regval_t *regvals)
{
  for ( int i=dbg->registers_size - 1; i >= 0; i-- )
  {
    if ( stricmp(name, dbg->registers[i].name) == 0 )
      return &regvals[i];
  }
  static regval_t rv;
  return &rv;
}

//-------------------------------------------------------------------------
//</code(py_idp)>
%}