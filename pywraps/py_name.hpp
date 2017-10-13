//-------------------------------------------------------------------------
//<code(py_name)>
//</code(py_name)>

//------------------------------------------------------------------------
//<inline(py_name)>
//------------------------------------------------------------------------
PyObject *py_get_debug_names(ea_t ea1, ea_t ea2)
{
  // Get debug names
  ea_name_vec_t names;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  Py_BEGIN_ALLOW_THREADS;
  get_debug_names(&names, ea1, ea2);
  Py_END_ALLOW_THREADS;
  PyObject *dict = Py_BuildValue("{}");
  if ( dict != NULL )
  {
    for ( ea_name_vec_t::iterator it=names.begin(); it != names.end(); ++it )
    {
      PyDict_SetItem(dict,
                     Py_BuildValue(PY_BV_EA, bvea_t(it->ea)),
                     PyString_FromString(it->name.c_str()));
    }
  }
  return dict;
}

//-------------------------------------------------------------------------
inline qstring py_get_ea_name(ea_t ea, int gtn_flags=0)
{
  qstring out;
  get_ea_name(&out, ea, gtn_flags);
  return out;
}

//-------------------------------------------------------------------------
PyObject *py_validate_name(const char *name, nametype_t type, int flags=0)
{
  qstring qname(name);
  if ( validate_name(&qname, type, flags) )
    return PyString_FromStringAndSize(qname.c_str(), qname.length());
  else
    Py_RETURN_NONE;
}
//</inline(py_name)>
