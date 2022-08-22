
//<inline(py_lumina)>

//-------------------------------------------------------------------------
bool py_extract_type_from_metadata(tinfo_t *out, const bytevec_t &in)
{
  md_type_parts_t tp;
  if ( !in.empty() )
  {
    const uchar *ptr = in.begin();
    const uchar *end = in.end();
    extract_type_from_metadata(&tp, ptr, end);
    out->deserialize(nullptr, &tp.type, &tp.fields);
  }
  return tp.userti;
}

//-------------------------------------------------------------------------
PyObject *py_split_metadata(const metadata_t &md)
{
  PyObject *py_dict = PyDict_New();

  metadata_iterator_t p(md);
  while ( p.next() )
  {
    newref_t py_key(PyInt_FromLong(p.key));
    newref_t py_value(PyBytes_FromStringAndSize((const char *) p.data, p.size));
    // PyDict_SetItem doesn't "steal" references; hence the 'newref_t's above.
    PyDict_SetItem(py_dict, py_key.o, py_value.o);
  }

  return py_dict;
}

//</inline(py_lumina)>
