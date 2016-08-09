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
  for ( Py_ssize_t i=0; i < ph.regsNum; i++ )
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
