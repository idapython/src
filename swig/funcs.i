
%import "range.i"

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

%template (stkpnt_array) dynamic_wrapped_array_t<stkpnt_t>;
%template (regvar_array) dynamic_wrapped_array_t<regvar_t>;
%template (range_array) dynamic_wrapped_array_t<range_t>;

%extend func_t
{
  dynamic_wrapped_array_t<stkpnt_t> __get_points__()
  {
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

  %pythoncode {
    points = property(__get_points__)
    regvars = property(__get_regvars__)
    tails = property(__get_tails__)
  }
}

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
