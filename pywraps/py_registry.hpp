
#ifndef __PY_REGISTRY__
#define __PY_REGISTRY__

//<code(py_registry)>
//-------------------------------------------------------------------------
static PyObject *_py_reg_subkey_children(const char *name, bool subkeys)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  PyObject *result = NULL;
  qstrvec_t children;
  Py_BEGIN_ALLOW_THREADS;
  if ( reg_subkey_children(&children, name, subkeys) )
  {
    result = PyList_New(children.size());
    if ( result != NULL )
      for ( size_t i = 0, n = children.size(); i < n; ++i )
        PyList_SET_ITEM(result, i, IDAPyStr_FromUTF8(children[i].c_str()));
  }
  Py_END_ALLOW_THREADS;
  if ( result == NULL )
    Py_RETURN_NONE;
  else
    return result;
}
//</code(py_registry)>


//<inline(py_registry)>
//-------------------------------------------------------------------------
PyObject *py_reg_read_string(const char *name, const char *subkey = NULL, const char *def = NULL)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring utf8;
  bool ok;
  Py_BEGIN_ALLOW_THREADS;
  if ( !reg_read_string(&utf8, name, subkey) && def != NULL )
    utf8 = def;
  Py_END_ALLOW_THREADS;
  return IDAPyStr_FromUTF8(utf8.c_str());
}

//-------------------------------------------------------------------------
regval_type_t py_reg_data_type(const char *name, const char *subkey = NULL)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  regval_type_t rt = reg_unknown;
  Py_BEGIN_ALLOW_THREADS;
  reg_data_type(&rt, name, subkey);
  Py_END_ALLOW_THREADS;
  return rt;
}

//-------------------------------------------------------------------------
PyObject *py_reg_read_binary(const char *name, const char *subkey = NULL)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bytevec_t bytes;
  bool ok;
  Py_BEGIN_ALLOW_THREADS;
  ok = reg_read_binary(name, &bytes, subkey);
  Py_END_ALLOW_THREADS;
  if ( ok )
    return IDAPyBytes_FromMemAndSize((const char *) bytes.begin(), bytes.size());
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
PyObject *py_reg_write_binary(const char *name, PyObject *py_bytes, const char *subkey = NULL)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( IDAPyBytes_Check(py_bytes) )
  {
    char *py_bytes_raw = NULL;
    Py_ssize_t py_size = 0;
    IDAPyBytes_AsMemAndSize(py_bytes, &py_bytes_raw, &py_size);
    bytevec_t bytes;
    bytes.append(py_bytes_raw, py_size);
    Py_BEGIN_ALLOW_THREADS;
    reg_write_binary(name, bytes.begin(), bytes.size(), subkey);
    Py_END_ALLOW_THREADS;
    Py_RETURN_NONE;
  }
  else
  {
    PyErr_SetString(PyExc_ValueError, "Bytes string expected!");
    return NULL;
  }
}

//-------------------------------------------------------------------------
PyObject *py_reg_subkey_subkeys(const char *name)
{
  return _py_reg_subkey_children(name, true);
}

//-------------------------------------------------------------------------
PyObject *py_reg_subkey_values(const char *name)
{
  return _py_reg_subkey_children(name, false);
}

//</inline(py_registry)>


#endif // __PY_REGISTRY__
