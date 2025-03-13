
//<inline(py_funcs)>

#ifndef FUNC_STATICDEF
#define FUNC_STATICDEF  0x00000008
#endif

//-----------------------------------------------------------------------
static ea_t get_fchunk_referer(ea_t ea, size_t idx)
{
  func_t *pfn = get_fchunk(ea);
  if ( !is_func_tail(pfn) )
    return BADADDR;
  func_parent_iterator_t dummy(pfn); // read referer info
  if ( idx >= pfn->refqty || pfn->referers == nullptr )
    return BADADDR;
  else
    return pfn->referers[idx];
}

//-----------------------------------------------------------------------
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
