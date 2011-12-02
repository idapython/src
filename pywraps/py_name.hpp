//------------------------------------------------------------------------
//<inline(py_name)>
//------------------------------------------------------------------------
PyObject *py_get_debug_names(ea_t ea1, ea_t ea2)
{
  // Get debug names
  ea_name_vec_t names;
  get_debug_names(ea1, ea2, names);
  PyObject *dict = Py_BuildValue("{}");
  if (dict == NULL)
    return NULL;

  for (ea_name_vec_t::iterator it=names.begin();it!=names.end();++it)
  {
    PyDict_SetItem(dict,
      Py_BuildValue(PY_FMT64, it->ea),
      PyString_FromString(it->name.c_str()));
  }
  return dict;
}
//------------------------------------------------------------------------
//</inline(py_name)>
//------------------------------------------------------------------------
