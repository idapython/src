//-------------------------------------------------------------------------
//<code(py_name)>
//</code(py_name)>

//------------------------------------------------------------------------
//<inline(py_name)>
//------------------------------------------------------------------------
PyObject *get_debug_names(ea_t ea1, ea_t ea2, bool return_list=false)
{
  // Get debug names
  ea_name_vec_t names;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  get_debug_names(&names, ea1, ea2);
  SWIG_PYTHON_THREAD_END_ALLOW;
  PyObject *dict = Py_BuildValue("{}");
  if ( dict != nullptr )
  {
    ea_t last_ea = BADADDR;
    PyObject *list = nullptr;
    for ( ea_name_vec_t::iterator it = names.begin(); it != names.end(); ++it )
    {
      PyObject *name_obj = PyUnicode_FromString(it->name.c_str());
      if ( it->ea != last_ea )
      {
        if ( return_list )
          list = PyList_New(0);
        PyObject *ea_obj = Py_BuildValue(PY_BV_EA, bvea_t(it->ea));
        PyDict_SetItem(dict, ea_obj, return_list ? list : name_obj);
        last_ea = it->ea;
      }
      if ( return_list )
        PyList_Append(list, name_obj);
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
    return PyUnicode_FromStringAndSize(qname.c_str(), qname.length());
  else
    Py_RETURN_NONE;
}
//</inline(py_name)>
