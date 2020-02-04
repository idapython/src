%module(docstring="IDA Plugin SDK API wrapper: ua",directors="1",threads="1") ida_ua
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_UA
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_UA
  #define HAS_DEP_ON_INTERFACE_UA
#endif
%include "header.i"
%{
#include <ua.hpp>
#include <frame.hpp>
%}

%ignore print_charlit;
%ignore format_charlit;
%ignore print_fpval;
%ignore get_spoiled_reg;
%ignore decode_preceding_insn;
%ignore get_operand_immvals;
%ignore get_immvals;
%rename (get_immvals) py_get_immvals;
%ignore get_printable_immvals;
%rename (get_printable_immvals) py_get_printable_immvals;
%ignore get_immval;
%ignore insn_create_op_data;

%ignore construct_macro;
%ignore API70_construct_macro;
%rename (construct_macro) py_construct_macro;
%ignore get_dtype_by_size;
%rename (get_dtype_by_size) py_get_dtype_by_size;
%ignore outctx_base_t::print_hex_dump;
%ignore outctx_base_t::add_spaces;
%ignore outctx_base_t::nowarn_out_printf;
%ignore outctx_base_t::out_vprintf;
%ignore outctx_base_t::gen_colored_cmt_line_v;
%ignore outctx_base_t::gen_cmt_line_v;
%ignore outctx_base_t::gen_vprintf;
%ignore outctx_base_t::get_xrefgen_state;
%ignore outctx_base_t::get_cmtgen_state;

%ignore outctx_base_t::regname_idx;
%ignore outctx_base_t::suspop;
%ignore outctx_base_t::F;
%ignore outctx_base_t::outvalues;
%ignore outctx_base_t::outvalue_getn_flags;
%ignore outctx_base_t::user_data;
%ignore outctx_base_t::kern_data;
%ignore outctx_base_t::lnar;
%ignore outctx_base_t::lnar_maxsize;
%ignore outctx_base_t::line_prefix;
%ignore outctx_base_t::prefix_len;
%ignore outctx_base_t::ctxflags;
%ignore outctx_base_t::ind0;
%ignore outctx_base_t::cmt_ea;
%ignore outctx_base_t::cmtbuf;
%ignore outctx_base_t::cmtptr;
%ignore outctx_base_t::cmtcolor;

%template (operands_array) wrapped_array_t<op_t,UA_MAXOP>;

%feature("nodirector") outctx_base_t;
%feature("nodirector") outctx_t;

%ignore outctx_base_t::outctx_base_t;
%ignore outctx_base_t::~outctx_base_t;
%ignore outctx_t::outctx_t;
%ignore outctx_t::~outctx_t;

%extend insn_t
{
  wrapped_array_t<op_t,UA_MAXOP> __get_ops__()
  {
    return wrapped_array_t<op_t,UA_MAXOP>($self->ops);
  }
  op_t *__get_operand__(int n) { QASSERT(30502, n >= 0 && n < UA_MAXOP); return &($self->ops[n]); }
  uint16 __get_auxpref__() { return $self->auxpref;  }
  void __set_auxpref__(uint16 v) { $self->auxpref = v; }

  void assign(const insn_t &other) { *($self) = other; }

  %pythoncode {
    ops = property(__get_ops__)
#ifdef BC695
    if _BC695:
        Operands = ops
#endif
    Op1 = property(lambda self: self.__get_operand__(0))
    Op2 = property(lambda self: self.__get_operand__(1))
    Op3 = property(lambda self: self.__get_operand__(2))
    Op4 = property(lambda self: self.__get_operand__(3))
    Op5 = property(lambda self: self.__get_operand__(4))
    Op6 = property(lambda self: self.__get_operand__(5))

    auxpref = property(__get_auxpref__, __set_auxpref__)

    def __iter__(self):
        return (self.ops[idx] for idx in xrange(0, UA_MAXOP))

    def __getitem__(self, idx):
        """
        Operands can be accessed directly as indexes
        @return op_t: Returns an operand of type op_t
        """
        if idx >= UA_MAXOP:
            raise KeyError
        else:
            return self.ops[idx]
  }
}

%extend op_t
{
  uint16 __get_reg_phrase__() { return $self->reg;  }
  void __set_reg_phrase__(uint16 r) { $self->reg = r; }

  // use ea_t so the right value decoders will be used (for the next three)
  ea_t __get_value__() { return $self->value; }
  void __set_value__(ea_t v) { $self->value = v; }
  ea_t __get_addr__() { return $self->addr; }
  void __set_addr__(ea_t v) { $self->addr = v; }
  ea_t __get_specval__() { return $self->specval; }
  void __set_specval__(ea_t v) { $self->specval = v; }

  void assign(const op_t &other) { *($self) = other; }

  %pythoncode {
    def has_reg(self, r):
        """Checks if the operand accesses the given processor register"""
        return self.reg == r.reg

    reg = property(__get_reg_phrase__, __set_reg_phrase__)
    phrase = property(__get_reg_phrase__, __set_reg_phrase__)
    value = property(__get_value__, __set_value__)
    addr = property(__get_addr__, __set_addr__)
    specval = property(__get_specval__, __set_specval__)
  }
}
/* // @arnaud types! */
%apply uchar { char offb };
%apply uchar { char offo };
%apply uchar { op_dtype_t dtype };
%apply uchar { char specflag1 };
%apply uchar { char specflag2 };
%apply uchar { char specflag3 };
%apply uchar { char specflag4 };
%apply uchar { char flags };


%apply ea_t { adiff_t off };
%apply ea_t { adiff_t off };

%include "ua.hpp"

%rename (decode_preceding_insn) py_decode_preceding_insn;

%{
//<code(py_ua)>
//</code(py_ua)>
%}

%inline %{
//<inline(py_ua)>
/*
#<pydoc>
def decode_preceding_insn(ea):
    """
    Decodes the preceding instruction. Please check ua.hpp / decode_preceding_insn()
    @param ea: current ea
    @param out: instruction storage
    @return: tuple(preceeding_ea or BADADDR, farref = Boolean)
    """
    pass
#</pydoc>
*/
PyObject *py_decode_preceding_insn(insn_t *out, ea_t ea)
{
  bool farref;
  ea_t r = decode_preceding_insn(out, ea, &farref);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  return Py_BuildValue("(" PY_BV_EA "i)", bvea_t(r), farref ? 1 : 0);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def construct_macro(insn):
    """
    See ua.hpp's construct_macro().
    """
    pass
#</pydoc>
*/
bool py_construct_macro(insn_t &insn, bool enable, PyObject *build_macro)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  if ( !PyCallable_Check(build_macro) )
    return false;

  static qstack<ref_t> macro_builders;

  macro_builders.push(newref_t(build_macro));
  struct ida_local lambda_t
  {
    static bool idaapi call_build_macro(insn_t &insn, bool may_go_forward)
    {
      PyObject *py_builder = macro_builders.top().o;
      ref_t py_res;
      ref_t py_mod(PyW_TryImportModule(SWIG_name));
      if ( py_mod != NULL )
      {
        ref_t py_insn = try_create_swig_wrapper(py_mod, "insn_t", &insn);
        if ( py_insn != NULL )
        {
          py_res = newref_t(
                  PyObject_CallFunction(
                          py_builder,
                          "OO",
                          py_insn.o,
                          may_go_forward ? Py_True : Py_False));
          PyW_ShowCbErr("build_macro");
        }
      }
      return py_res.o == Py_True;
    }
  };
  bool res = construct_macro(insn, enable, lambda_t::call_build_macro);
  macro_builders.pop();
  return res;
}

//-------------------------------------------------------------------------
static int py_get_dtype_by_size(asize_t size)
{
  return int(get_dtype_by_size(size));
}

//-------------------------------------------------------------------------
PyObject *py_get_immvals(ea_t ea, int n, flags_t F=0)
{
  uvalvec_t storage;
  storage.resize(2 * UA_MAXOP);
  if ( F == 0 )
    F = get_flags(ea);
  size_t cnt = get_immvals(storage.begin(), ea, n, F);
  storage.resize(cnt);
  ref_t result(PyW_UvalVecToPyList(storage));
  result.incref();
  return result.o;
}

//-------------------------------------------------------------------------
PyObject *py_get_printable_immvals(ea_t ea, int n, flags_t F=0)
{
  uvalvec_t storage;
  storage.resize(2 * UA_MAXOP);
  if ( F == 0 )
    F = get_flags(ea);
  size_t cnt = get_printable_immvals(storage.begin(), ea, n, F);
  storage.resize(cnt);
  ref_t result(PyW_UvalVecToPyList(storage));
  result.incref();
  return result.o;
}

//-------------------------------------------------------------------------
#define DEFINE_WRAP_TYPE_FROM_PTRVAL(Type)              \
  static Type *Type##__from_ptrval__(size_t ptrval)     \
  {                                                     \
    return (Type *) ptrval;                             \
  }

DEFINE_WRAP_TYPE_FROM_PTRVAL(insn_t);
DEFINE_WRAP_TYPE_FROM_PTRVAL(op_t);
DEFINE_WRAP_TYPE_FROM_PTRVAL(outctx_base_t);
DEFINE_WRAP_TYPE_FROM_PTRVAL(outctx_t);

#undef DEFINE_WRAP_TYPE_FROM_PTRVAL

//</inline(py_ua)>
%}

%pythoncode %{
#<pycode(py_ua)>
ua_mnem = print_insn_mnem
#</pycode(py_ua)>
%}
%pythoncode %{
if _BC695:
    import ida_idaapi
    def codeSeg(ea, opnum):
        insn = insn_t()
        if decode_insn(insn, ea):
            return _ida_ua.map_code_ea(insn, insn.ops[opnum])
        else:
            return ida_idaapi.BADADDR
    get_dtyp_by_size=get_dtype_by_size
    get_dtyp_flag=get_dtype_flag
    get_dtyp_size=get_dtype_size
    get_operand_immvals=get_immvals
    op_t.dtyp = op_t.dtype
    cmd = insn_t()
    @bc695redef
    def decode_insn(*args):
        if len(args) == 1:
            tmp = insn_t()
            rc = _ida_ua.decode_insn(tmp, args[0])
            cmd.assign(tmp)
            return rc
        else:
            return _ida_ua.decode_insn(*args)
    @bc695redef
    def create_insn(*args):
        if len(args) == 1:
            tmp = insn_t()
            rc = _ida_ua.create_insn(args[0], tmp)
            cmd.assign(tmp)
            return rc
        else:
            return _ida_ua.create_insn(*args)
    @bc695redef
    def decode_prev_insn(*args):
        if len(args) == 1:
            tmp = insn_t()
            rc = _ida_ua.decode_prev_insn(tmp, args[0])
            cmd.assign(tmp)
            return rc
        else:
            return _ida_ua.decode_prev_insn(*args)
    @bc695redef
    def decode_preceding_insn(*args):
        if len(args) == 1:
            tmp = insn_t()
            rc = _ida_ua.decode_preceding_insn(tmp, args[0])
            cmd.assign(tmp)
            return rc
        else:
            return _ida_ua.decode_preceding_insn(*args)
    import ida_ida
    UA_MAXOP=ida_ida.UA_MAXOP
    dt_3byte=dt_byte
    tbo_123=0
    tbo_132=0
    tbo_213=0
    tbo_231=0
    tbo_312=0
    tbo_321=0
    def ua_add_cref(opoff, to, rtype):
        return cmd.add_cref(to, opoff, rtype)
    def ua_add_dref(opoff, to, rtype):
        return cmd.add_dref(to, opoff, rtype)
    def ua_add_off_drefs(x, rtype):
        return cmd.add_off_drefs(x, rtype, 0)
    def ua_add_off_drefs2(x, rtype, outf):
        return cmd.add_off_drefs(x, rtype, outf)
    def ua_dodata(ea, dtype):
        return cmd.create_op_data(ea, 0, dtype)
    def ua_dodata2(opoff, ea, dtype):
        return cmd.create_op_data(ea, opoff, dtype)
    def ua_stkvar2(x, v, flags):
        return cmd.create_stkvar(x, v, flags)

%}