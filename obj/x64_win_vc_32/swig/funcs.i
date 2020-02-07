%module(docstring="IDA Plugin SDK API wrapper: funcs",directors="1",threads="1") ida_funcs
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_FUNCS
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_FUNCS
  #define HAS_DEP_ON_INTERFACE_FUNCS
#endif
#ifndef HAS_DEP_ON_INTERFACE_RANGE
  #define HAS_DEP_ON_INTERFACE_RANGE
#endif
%include "header.i"

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
%typemap(check) (func_t  * pfn, ea_t * fptr)
{
if ( $1 == NULL )
  SWIG_exception_fail(SWIG_ValueError, "invalid null reference in method '$symname', argument $argnum of type '$1_type'");
}
//</typemaps(funcs)>

%apply ea_t *result { ea_t *fptr }; // calc_thunk_func_target()
%apply ea_t *appended_ea { ea_t *fptr };

%include "funcs.hpp"

%clear(char *buf);
%clear(char *optlibs);

%inline %{
//<inline(py_funcs)>

#ifndef FUNC_STATICDEF
#define FUNC_STATICDEF  0x00000008
#endif

//-----------------------------------------------------------------------
/*
#<pydoc>
def get_fchunk_referer(ea, idx):
    pass
#</pydoc>
*/
static ea_t get_fchunk_referer(ea_t ea, size_t idx)
{
  func_t *pfn = get_fchunk(ea);
  if ( pfn == NULL )
    return BADADDR;
  func_parent_iterator_t dummy(pfn); // read referer info
  if ( idx >= pfn->refqty || pfn->referers == NULL )
    return BADADDR;
  else
    return pfn->referers[idx];
}

//-----------------------------------------------------------------------
/*
#<pydoc>
def get_idasgn_desc(n):
    """
    Get information about a signature in the list.
    It returns: (name of signature, names of optional libraries)

    See also: get_idasgn_desc_with_matches

    @param n: number of signature in the list (0..get_idasgn_qty()-1)
    @return: None on failure or tuple(signame, optlibs)
    """
    pass
#</pydoc>
*/
static PyObject *py_get_idasgn_desc(int n)
{
  qstring signame;
  qstring optlibs;

  if ( get_idasgn_desc(&signame, &optlibs, n) < 0 )
    Py_RETURN_NONE;
  else
    return Py_BuildValue("(ss)", signame.c_str(), optlibs.c_str());
}

//-----------------------------------------------------------------------
/*
#<pydoc>
def get_idasgn_desc_with_matches(n):
    """
    Get information about a signature in the list.
    It returns: (name of signature, names of optional libraries, number of matches)

    @param n: number of signature in the list (0..get_idasgn_qty()-1)
    @return: None on failure or tuple(signame, optlibs, nmatches)
    """
    pass
#</pydoc>
*/
static PyObject *py_get_idasgn_desc_with_matches(int n)
{
  qstring signame;
  qstring optlibs;

  int32 matches = get_idasgn_desc(&signame, &optlibs, n);
  if ( matches < 0 )
    Py_RETURN_NONE;
  else
    return Py_BuildValue("(ssi)", signame.c_str(), optlibs.c_str(), matches);
}

//-------------------------------------------------------------------------
static func_t *func_t__from_ptrval__(size_t ptrval)
{
  return (func_t *) ptrval;
}
//</inline(py_funcs)>
%}

%pythoncode %{
#<pycode(py_funcs)>
import ida_idaapi
@ida_idaapi.replfun
def calc_thunk_func_target(*args):
    if len(args) == 2:
        pfn, rawptr = args
        target, fptr = calc_thunk_func_target.__dict__["orig"](pfn)
        import ida_pro
        ida_pro.ea_pointer.frompointer(rawptr).assign(fptr)
        return target
    else:
        return calc_thunk_func_target.__dict__["orig"](*args)
#</pycode(py_funcs)>
%}
%pythoncode %{
if _BC695:
    FUNC_STATIC=FUNC_STATICDEF
    add_regarg2=add_regarg
    clear_func_struct=lambda *args: True
    def del_func_cmt(pfn, rpt):
        set_func_cmt(pfn, "", rpt)
    func_parent_iterator_set2=func_parent_iterator_set
    func_setend=set_func_end
    func_setstart=set_func_start
    func_tail_iterator_set2=func_tail_iterator_set
    def get_func_limits(pfn, limits):
        import ida_range
        rs = ida_range.rangeset_t()
        if get_func_ranges(rs, pfn) == ida_idaapi.BADADDR:
            return False
        limits.start_ea = rs.begin().start_ea
        limits.end_ea = rs.begin().end_ea
        return True
    get_func_name2=get_func_name

%}