%{
#include <regfinder.hpp>
%}

//-------------------------------------------------------------------------
// ignore not published structs
%ignore reg_finder_op_t;
%ignore reg_finder_t;

//-------------------------------------------------------------------------
%immutable reg_value_def_t::SHORT_INSN;
%immutable reg_value_def_t::PC_BASED;
%immutable reg_value_def_t::LIKE_GOT;
%ignore reg_value_def_t::val_eq;
%ignore reg_value_def_t::val_less;

//-------------------------------------------------------------------------
// dstr() as str()
%ignore reg_value_info_t::dstr;
%extend reg_value_info_t
{
  inline qstring __str__() const { return $self->dstr(); }
}

//-------------------------------------------------------------------------
// ignore helpers
%ignore reg_finder_invalidate_cache(reg_finder_t *_this, ea_t ea);
%ignore reg_finder_find(reg_finder_t *_this, reg_value_info_t *out, ea_t ea, ea_t ds, reg_finder_op_t op, int max_depth);
%ignore reg_finder_calc_op_addr(reg_finder_t *_this, reg_value_info_t *addr, const op_t *memop, const insn_t *insn, ea_t ea, ea_t ds);
%ignore reg_finder_emulate_mem_read(reg_finder_t *_this, reg_value_info_t *value, const reg_value_info_t *addr, int width, bool is_signed, const insn_t *insn);
%ignore reg_finder_emulate_binary_op(reg_finder_t *_this, reg_value_info_t *value, int aop, const op_t *op1, const op_t *op2, const insn_t *insn, ea_t ea, ea_t ds, reg_finder_binary_ops_adjust_fun adjust, void *ud);
%ignore reg_finder_emulate_unary_op(reg_finder_t *_this, reg_value_info_t *value, int aop, int reg, const insn_t *insn, ea_t ea, ea_t ds);
%ignore reg_finder_may_modify_stkvars(const reg_finder_t *_this, reg_finder_op_t op, const insn_t *insn);
%ignore reg_finder_ctr(reg_finder_t *_this);
%ignore reg_finder_dtr(reg_finder_t *_this);
%ignore reg_value_def_dstr(const reg_value_def_t *_this, qstring *vout, int how, const procmod_t *pm);
%ignore reg_value_info_dstr(const reg_value_info_t *_this, qstring *vout, const procmod_t *pm);
%ignore reg_value_info_vals_union(reg_value_info_t *_this, const reg_value_info_t *r);
%ignore reg_finder_op_make_rfop(func_t *pfn, const insn_t *insn, const op_t *op);

//-------------------------------------------------------------------------
// add access to reg_value_info_t::vals
%ignore reg_value_info_t::vals_begin;
%ignore reg_value_info_t::vals_end;
%ignore reg_value_info_t::vals_size;
%extend reg_value_info_t
{
  inline size_t __len__() const { return $self->vals_size(); }
  inline const reg_value_def_t &__getitem__(size_t i) const
  {
    if ( i >= $self->vals_size() )
      throw std::out_of_range("out of bounds access");
    return $self->vals_begin()[i];
  }
}

//-------------------------------------------------------------------------
// For 'find_reg_value()'
%define %val_t_result_as_output(TYPE, CONVFUNC, NAME)
%typemap(in,numinputs=0) TYPE *NAME (TYPE temp = 0)
{
  // %val_t_result_as_output(TYPE, CONVFUNC, NAME) %typemap(in,numinputs=0)
  $1 = &temp;
}
%typemap(argout) TYPE *NAME
{
  // %val_t_result_as_output(TYPE, CONVFUNC, NAME) %typemap(argout)
  Py_XDECREF(resultobj);
  if ( result == 1 )
  {
    resultobj = CONVFUNC(*(TYPE *) $1);
  }
  else if ( result == 0 )
  {
    Py_INCREF(Py_None);
    resultobj = Py_None;
  }
  else
  {
    SWIG_exception_fail(SWIG_RuntimeError, "The processor module does not support a register tracker");
  }
}
%enddef
%val_t_result_as_output(uint32, PyLong_FromUnsignedLong, uval);
%val_t_result_as_output(uint64, PyLong_FromUnsignedLongLong, uval);
%val_t_result_as_output(int32, PyLong_FromLong, sval);
%val_t_result_as_output(int64, PyLong_FromLongLong, sval);

//-------------------------------------------------------------------------
// For 'find_nearest_rvi()'
%typemap(in) int reg[2] (int temp[2])
{
  // %typemap(in) int reg[2] (int temp[2])
  if ( !PyTuple_Check($input)
    || PyTuple_Size($input) != 2
    || !PyLong_Check(PyTuple_GetItem($input, 0))
    || !PyLong_Check(PyTuple_GetItem($input, 1)) )
  {
    SWIG_exception_fail(
            SWIG_TypeError,
            "in method '" "$symname" "', argument " "$argnum"" of type (long, long)");
  }

  temp[0] = PyLong_AsLong(PyTuple_GetItem($input, 0));
  temp[1] = PyLong_AsLong(PyTuple_GetItem($input, 1));
  $1 = temp;
}

%include "regfinder.hpp"
