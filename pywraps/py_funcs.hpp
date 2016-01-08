
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
  char signame[MAXSTR];
  char optlibs[MAXSTR];

  if ( get_idasgn_desc(n, signame, sizeof(signame), optlibs, sizeof(optlibs)) < 0 )
    Py_RETURN_NONE;
  else
    return Py_BuildValue("(ss)", signame, optlibs);
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
  char signame[MAXSTR];
  char optlibs[MAXSTR];

  int32 matches = get_idasgn_desc(n, signame, sizeof(signame), optlibs, sizeof(optlibs));
  if ( matches < 0 )
    Py_RETURN_NONE;
  else
    return Py_BuildValue("(ssi)", signame, optlibs, matches);
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

//</inline(py_funcs)>
