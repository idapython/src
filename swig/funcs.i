%cstring_bounded_output_none(char *buf, MAXSTR);
%cstring_bounded_output_none(char *optlibs, MAXSTR);

// FIXME: Are these really useful?
%ignore iterate_func_chunks;
%ignore get_idasgn_header_by_short_name;

// Kernel-only & unexported symbols
%ignore del_regargs;
%ignore write_regargs;
%ignore find_regarg;
%ignore free_regarg;
%ignore determine_rtl;
%ignore init_signatures;
%ignore save_signatures;
%ignore term_signatures;
%ignore init_funcs;
%ignore save_funcs;
%ignore term_funcs;
%ignore move_funcs;
%ignore copy_noret_info;
%ignore recalc_func_noret_flag;
%ignore plan_for_noret_analysis;
%ignore invalidate_sp_analysis;

%ignore create_func_eas_array;
%ignore auto_add_func_tails;
%ignore read_tails;

%ignore get_idasgn_desc;
%rename (get_idasgn_desc) py_get_idasgn_desc;

%ignore get_func_cmt;
%rename (get_func_cmt) py_get_func_cmt;

%include "funcs.hpp"

%clear(char *buf);
%clear(char *optlibs);

%inline %{
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
    func_parent_iterator_t dummy(pfn); // read referer info
    if (idx >= pfn->refqty || pfn->referers == NULL)
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
    It returns both:
      signame - the name of the signature
      optlibs - the names of the optional libraries

    @param n: number of signature in the list (0..get_idasgn_qty()-1)
    @return: None on failure or tuple(signame, optlibs)
    """
    pass
#</pydoc>
*/
static PyObject *py_get_idasgn_desc(int n)
{
  char signame[MAXSTR];
  char optlibs[MAXSTR];

  if ( get_idasgn_desc(n, signame, sizeof(signame), optlibs, sizeof(optlibs)) == -1 )
    Py_RETURN_NONE;
  else
    return Py_BuildValue("(ss)", signame, optlibs);
}

//-----------------------------------------------------------------------
/*
#<pydoc>
def get_func_cmt(fn, repeatable):
    """
    Retrieve function comment
    @param fn: function instance
    @param repeatable: retrieve repeatable or non-repeatable comments
    @return: None on failure or the comment
    """
    pass
#</pydoc>
*/
static PyObject *py_get_func_cmt(func_t *fn, bool repeatable)
{
  char *s = get_func_cmt(fn, repeatable);
  if ( s == NULL )
  {
    Py_RETURN_NONE;
  }
  else
  {
    PyObject *py_s = PyString_FromString(s);
    qfree(s);
    return py_s;
  }
}
%}
