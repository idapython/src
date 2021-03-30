
%{
#include <frame.hpp>
%}

// FIXME: Are these really useful?
%ignore iterate_func_chunks;
%ignore get_idasgn_header_by_short_name;

// Kernel-only & unexported symbols
%ignore determine_rtl;
%ignore save_signatures;
%ignore invalidate_sp_analysis;

%ignore get_idasgn_desc;
%rename (get_idasgn_desc) py_get_idasgn_desc;
%rename (get_idasgn_desc_with_matches) py_get_idasgn_desc_with_matches;

%ignore func_md_t::cbsize;
%ignore func_pat_t::cbsize;

%ignore func_t::llabelqty;
%ignore func_t::llabels;
%ignore FUNC_RESERVED;

%template (dyn_stkpnt_array) dynamic_wrapped_array_t<stkpnt_t>;
%template (dyn_regvar_array) dynamic_wrapped_array_t<regvar_t>;
%template (dyn_range_array) dynamic_wrapped_array_t<range_t>;
%template (dyn_ea_array) dynamic_wrapped_array_t<ea_t>;
%template (dyn_regarg_array) dynamic_wrapped_array_t<regarg_t>;

%extend func_t
{
  dynamic_wrapped_array_t<stkpnt_t> __get_points__()
  {
    if ( $self->pntqty > 0 && $self->points == NULL ) // force load
      get_sp_delta($self, $self->start_ea);
    return dynamic_wrapped_array_t<stkpnt_t>($self->points, $self->pntqty);
  }

  dynamic_wrapped_array_t<regvar_t> __get_regvars__()
  {
    if ( $self->regvarqty < 0 ) // force load
      find_regvar($self, $self->start_ea, NULL);
    return dynamic_wrapped_array_t<regvar_t>($self->regvars, $self->regvarqty);
  }

  dynamic_wrapped_array_t<range_t> __get_tails__()
  {
    return dynamic_wrapped_array_t<range_t>($self->tails, $self->tailqty);
  }

  dynamic_wrapped_array_t<ea_t> __get_referers__()
  {
    return dynamic_wrapped_array_t<ea_t>($self->referers, $self->refqty);
  }

  dynamic_wrapped_array_t<regarg_t> __get_regargs__()
  {
    if ( $self->regargqty > 0 && $self->regargs == NULL ) // force load
      read_regargs($self);
    return dynamic_wrapped_array_t<regarg_t>($self->regargs, $self->regargqty);
  }

  %pythoncode {
    points = property(__get_points__)
    regvars = property(__get_regvars__)
    tails = property(__get_tails__)
    referers = property(__get_referers__)
    regargs = property(__get_regargs__)
  }
}

%rename (__next__) next;

%define %make_python2_iterator(TYPE)
%extend TYPE
{
  %pythoncode {
    next = __next__
  }
}
%enddef
%make_python2_iterator(func_tail_iterator_t);
%make_python2_iterator(func_item_iterator_t);
%make_python2_iterator(func_parent_iterator_t);

//<typemaps(funcs)>
//</typemaps(funcs)>

%apply ea_t *result { ea_t *fptr }; // calc_thunk_func_target()
%apply ea_t *appended_ea { ea_t *fptr };

%include "funcs.hpp"

%clear(char *buf);
%clear(char *optlibs);

%inline %{
//<inline(py_funcs)>
//</inline(py_funcs)>
%}

%pythoncode %{
#<pycode(py_funcs)>
#</pycode(py_funcs)>
%}
