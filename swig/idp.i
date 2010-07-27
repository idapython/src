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

%ignore free_processor_module;
%ignore read_config_file;

%ignore gen_idb_event;

%include "idp.hpp"
%feature("director") IDB_Hooks;
%feature("director") IDP_Hooks;
%inline %{
int idaapi IDB_Callback(void *ud, int notification_code, va_list va);
class IDB_Hooks 
{
public:
    virtual ~IDB_Hooks() {};

    bool hook() { return hook_to_notification_point(HT_IDB, IDB_Callback, this); }
    bool unhook() { return unhook_from_notification_point(HT_IDB, IDB_Callback, this); }
    /* Hook functions to override in Python */
    virtual int byte_patched(ea_t ea) { return 0; };
    virtual int cmt_changed(ea_t, bool repeatable_cmt) { return 0; };
    virtual int ti_changed(ea_t ea, const type_t *type, const p_list *fnames) { msg("ti_changed hook not supported yet\n"); return 0; };
    virtual int op_ti_changed(ea_t ea, int n, const type_t *type, const p_list *fnames) { msg("op_ti_changed hook not supported yet\n"); return 0; };
    virtual int op_type_changed(ea_t ea, int n) { return 0; };
    virtual int enum_created(enum_t id) { return 0; };
    virtual int enum_deleted(enum_t id) { return 0; };
    virtual int enum_bf_changed(enum_t id) { return 0; };
    virtual int enum_renamed(enum_t id) { return 0; };
    virtual int enum_cmt_changed(enum_t id) { return 0; };
    virtual int enum_member_created(enum_t id, const_t cid) { return 0; };
    virtual int enum_member_deleted(enum_t id, const_t cid) { return 0; };
    virtual int struc_created(tid_t struc_id) { return 0; };
    virtual int struc_deleted(tid_t struc_id) { return 0; };
    virtual int struc_renamed(struc_t *sptr) { return 0; };
    virtual int struc_expanded(struc_t *sptr) { return 0; };
    virtual int struc_cmt_changed(tid_t struc_id) { return 0; };
    virtual int struc_member_created(struc_t *sptr, member_t *mptr) { return 0; };
    virtual int struc_member_deleted(struc_t *sptr, tid_t member_id) { return 0; };
    virtual int struc_member_renamed(struc_t *sptr, member_t *mptr) { return 0; };
    virtual int struc_member_changed(struc_t *sptr, member_t *mptr) { return 0; };
    virtual int thunk_func_created(func_t *pfn) { return 0; };
    virtual int func_tail_appended(func_t *pfn, func_t *tail) { return 0; };
    virtual int func_tail_removed(func_t *pfn, ea_t tail_ea) { return 0; };
    virtual int tail_owner_changed(func_t *tail, ea_t owner_func) { return 0; };
    virtual int func_noret_changed(func_t *pfn) { return 0; };
    virtual int segm_added(segment_t *s) { return 0; };
    virtual int segm_deleted(ea_t startEA) { return 0; };
    virtual int segm_start_changed(segment_t *s) { return 0; };
    virtual int segm_end_changed(segment_t *s) { return 0; };
    virtual int segm_moved(ea_t from, ea_t to, asize_t size) { return 0; };
};

// Assemble an instruction into the database (display a warning if an error is found)
// args:
//  ea_t ea -  linear address of instruction
//  ea_t cs -  cs of instruction
//  ea_t ip -  ip of instruction
//  bool use32 - is 32bit segment?
//  const char *line - line to assemble
// returns: 1: success, 0: failure 
inline const int assemble(ea_t ea, ea_t cs, ea_t ip, bool use32, const char *line)
{
    int inslen;
    char buf[MAXSTR];

    if (ph.notify != NULL)
    {
        inslen =  ph.notify(ph.assemble, ea, cs, ip, use32, line, buf);
        if (inslen > 0)
	{
            patch_many_bytes(ea, buf, inslen);
            return 1;
	}
    }
    return 0;
}

//<inline(py_idp)>
//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
/*
#<pydoc>
def AssembleLine(ea, cs, ip, use32, line):
    """
    Assemble an instruction to a buffer (display a warning if an error is found)
    
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
static PyObject *AssembleLine(ea_t ea, ea_t cs, ea_t ip, bool use32, const char *line)
{
  int inslen;
  char buf[MAXSTR];
  if (ph.notify != NULL &&
    (inslen =  ph.notify(ph.assemble, ea, cs, ip, use32, line, buf)) > 0)
  {
    return PyString_FromStringAndSize(buf, inslen);
  }
  Py_RETURN_NONE;
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
  PyObject *py_result = PyTuple_New(ph.instruc_end - ph.instruc_start);
  for ( instruc_t *p = ph.instruc + ph.instruc_start, *end = ph.instruc + ph.instruc_end;
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
  PyObject *py_result = PyList_New(ph.regsNum);
  for ( Py_ssize_t i=0; i<ph.regsNum; i++ )
    PyList_SetItem(py_result, i, PyString_FromString(ph.regNames[i]));
  return py_result;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
class IDP_Hooks(object):
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

    def custom_mnem(self):
        """
        Prints the mnemonic of the instruction defined in idaapi.cmd

        @return:
            - None: No mnemonic. IDA will use the default mnemonic value if present
            - String: The desired mnemonic string
        """

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

    def is_sane_insn(self, no_crefs):
       """
       can a function start here?
       @param state: autoanalysis phase
             0: creating functions
             1: creating chunks
       
       @return: integer (probability 0..100)
       """
       pass
#</pydoc>
*/
int idaapi IDP_Callback(void *ud, int notification_code, va_list va);
class IDP_Hooks 
{
public:
  virtual ~IDP_Hooks() 
  {
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
    return NULL; 
  }

  virtual int is_sane_insn(int no_crefs)
  {
    return 0;
  }

  virtual int may_be_func(int state)
  {
    return 0;
  }
};

//</inline(py_idp)>
%}

%{
int idaapi IDB_Callback(void *ud, int notification_code, va_list va)
{
  class IDB_Hooks *proxy = (class IDB_Hooks *)ud;
  ea_t ea, ea2;
  bool repeatable_cmt;
  /*type_t *type;*/
  /*  p_list *fnames; */
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
#if 0
    case idb_event::ti_changed:
      ea = va_arg(va, ea_t);
      type = va_arg(va, type_t *);
      fnames = va_arg(va, fnames);
      return proxy->ti_changed(ea, type, fnames);

    case idb_event::op_ti_changed:
      ea = va_arg(va, ea_t);
      n = va_arg(va, int);
      type = va_arg(va, type_t *);
      fnames = va_arg(va, fnames);
      return proxy->op_ti_changed(ea, n, type, fnames);
#endif
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

    case idb_event::enum_member_created:
      id = va_arg(va, enum_t);
      cid = va_arg(va, const_t);
      return proxy->enum_member_created(id, cid);

    case idb_event::enum_member_deleted:
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
      return proxy->struc_member_deleted(sptr, member_id);

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
  catch (Swig::DirectorException &) 
  { 
    msg("Exception in IDB Hook function:\n"); 
    if (PyErr_Occurred())
    {
      PyErr_Print();
    }
  }
  return 0;
}

//<code(py_idp)>
//-------------------------------------------------------------------------
int idaapi IDP_Callback(void *ud, int notification_code, va_list va)
{
  IDP_Hooks *proxy = (IDP_Hooks *)ud;
  int ret;
  try 
  {
    switch ( notification_code )
    {
    default:
      ret = 0;
      break;

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
        PyObject *py_obj = create_idaapi_linked_class_instance(S_PY_OP_T_CLSNAME, op);
        if ( py_obj == NULL )
          break;
        ret = proxy->custom_outop(py_obj) ? 2 : 0;
        Py_XDECREF(py_obj);
        break;
      }

    case processor_t::custom_mnem:
      {
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
    }
  }
  catch (Swig::DirectorException &) 
  { 
    msg("Exception in IDP Hook function:\n"); 
    if ( PyErr_Occurred() )
      PyErr_Print();
  }
  return ret;
}

//-------------------------------------------------------------------------
//</code(py_idp)>
%}