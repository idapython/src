
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

%ignore func_item_iterator_next;
%ignore func_item_iterator_prev;
%ignore func_item_iterator_decode_prev_insn;
%ignore func_item_iterator_decode_preceding_insn;
%ignore func_item_iterator_succ;

%extend func_t
{
  dynamic_wrapped_array_t<stkpnt_t> __get_points__()
  {
    if ( $self->pntqty > 0 && $self->points == nullptr ) // force load
      get_sp_delta($self, $self->start_ea);
    return dynamic_wrapped_array_t<stkpnt_t>($self->points, $self->pntqty);
  }

  dynamic_wrapped_array_t<regvar_t> __get_regvars__()
  {
    if ( $self->regvarqty < 0 ) // force load
      find_regvar($self, $self->start_ea, nullptr);
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
    if ( $self->regargqty > 0 && $self->regargs == nullptr ) // force load
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

%define %def_simple_generator(TYPE, FUNC_NAME, START_FUNC, NEXT_FUNC, OBJ_FUNC, PYDOC)
%extend TYPE
{
  %pythoncode {
    def FUNC_NAME(self):
        """
        Provide an iterator on PYDOC
        """
        ok = self.START_FUNC()
        while ok:
            yield self.OBJ_FUNC()
            ok = self.NEXT_FUNC()
  }
}
%enddef

%define %def_simple_iterator_generator(TYPE, START_FUNC, NEXT_FUNC, OBJ_FUNC, PYDOC)
%def_simple_generator(TYPE, __iter__, START_FUNC, NEXT_FUNC, OBJ_FUNC, PYDOC);
// KLUDGE: Keep the 'next' attribute available
%extend TYPE
{
  %pythoncode {
    next = __next__
  }
}
%enddef
%def_simple_iterator_generator(func_tail_iterator_t, main, next, chunk, function tails);
%def_simple_iterator_generator(func_item_iterator_t, first, next_code, current, code items);
%def_simple_iterator_generator(func_parent_iterator_t, first, next, parent, function parents);

%define %def_simple_func_item_iterator_t_generator(FUNC_NAME, NEXT_NAME, PYDOC)
%def_simple_generator(func_item_iterator_t, FUNC_NAME, first, NEXT_NAME, current, PYDOC);
%enddef
%def_simple_func_item_iterator_t_generator(addresses, next_addr, addresses contained within the function);
%def_simple_func_item_iterator_t_generator(code_items, next_code, code items contained within the function);
%def_simple_func_item_iterator_t_generator(data_items, next_data, data items contained within the function);
%def_simple_func_item_iterator_t_generator(head_items, next_head, item heads contained within the function);
%def_simple_func_item_iterator_t_generator(not_tails, next_not_tail, non-tail addresses contained within the function);

%define %alias_func_item_iterator(PROP_NAME)
%extend func_t
{
  %pythoncode {
    def PROP_NAME(self):
        """
        Alias for func_item_iterator_t(self).PROP_NAME()
        """
        yield from func_item_iterator_t(self).PROP_NAME()
  }
}
%enddef
%alias_func_item_iterator(addresses);
%alias_func_item_iterator(code_items);
%alias_func_item_iterator(data_items);
%alias_func_item_iterator(head_items);
%alias_func_item_iterator(not_tails);

%extend func_t
{
  %pythoncode {
    def __iter__(self):
        """
        Alias for func_item_iterator_t(self).__iter__()
        """
        return func_item_iterator_t(self).__iter__()
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
