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
%ignore insn_get_next_byte;
%ignore insn_get_next_word;
%ignore insn_get_next_dword;
%ignore insn_get_next_qword;
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
%ignore outctx_base_t::get_binop_state;

%ignore outctx_base_t::regname_idx;
%ignore outctx_base_t::suspop;
%ignore outctx_base_t::F;
%ignore outctx_base_t::F_unused;
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
  uint32 __get_auxpref__() { return $self->auxpref;  }
  void __set_auxpref__(uint32 v) { $self->auxpref = v; }

  void assign(const insn_t &other) { *($self) = other; }

  bool is_canon_insn() const { return $self->is_canon_insn(PH); }
  uint32 get_canon_feature() const { return $self->get_canon_feature(PH); }
  const char *get_canon_mnem() const { return $self->get_canon_mnem(PH); }

  %pythoncode {
    ops = property(__get_ops__)
    Op1 = property(lambda self: self.__get_operand__(0))
    Op2 = property(lambda self: self.__get_operand__(1))
    Op3 = property(lambda self: self.__get_operand__(2))
    Op4 = property(lambda self: self.__get_operand__(3))
    Op5 = property(lambda self: self.__get_operand__(4))
    Op6 = property(lambda self: self.__get_operand__(5))
    Op7 = property(lambda self: self.__get_operand__(6))
    Op8 = property(lambda self: self.__get_operand__(7))

    auxpref = property(__get_auxpref__, __set_auxpref__)

    def __iter__(self):
        return (self.ops[idx] for idx in range(0, UA_MAXOP))

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
  uint64 __get_value64__() { return *((uint64 *)&$self->value); }
  void __set_value64__(uint64 v) { *((uint64 *)&$self->value) = v; }
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
    value64 = property(__get_value64__, __set_value64__)
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

%apply uchar { char segpref };
%apply uchar { char insnpref };

%include "ua.hpp"

%rename (decode_preceding_insn) py_decode_preceding_insn;

%{
//<code(py_ua)>
//</code(py_ua)>
%}

%inline %{
//<inline(py_ua)>
//</inline(py_ua)>
%}

%pythoncode %{
#<pycode(py_ua)>
#</pycode(py_ua)>
%}
