
#ifndef __PY_REGISTRY__
#define __PY_REGISTRY__

//<code(py_registry)>
//-------------------------------------------------------------------------
static PyObject *_py_reg_subkey_children(const char *name, bool subkeys)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstrvec_t children;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  bool ok = reg_subkey_children(&children, name, subkeys);
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( !ok )
    Py_RETURN_NONE;
  ref_t result = PyW_StrVecToPyList(children);
  result.incref();
  return result.o;
}
//</code(py_registry)>


//<inline(py_registry)>
//-------------------------------------------------------------------------
PyObject *py_reg_read_string(const char *name, const char *subkey = nullptr, const char *def = nullptr)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring utf8;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  if ( !reg_read_string(&utf8, name, subkey) && def != nullptr )
    utf8 = def;
  SWIG_PYTHON_THREAD_END_ALLOW;
  return PyUnicode_FromString(utf8.c_str());
}

//-------------------------------------------------------------------------
regval_type_t py_reg_data_type(const char *name, const char *subkey = nullptr)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  regval_type_t rt = reg_unknown;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  reg_data_type(&rt, name, subkey);
  SWIG_PYTHON_THREAD_END_ALLOW;
  return rt;
}

//-------------------------------------------------------------------------
PyObject *py_reg_read_binary(const char *name, const char *subkey = nullptr)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bytevec_t bytes;
  bool ok;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  ok = reg_read_binary(name, &bytes, subkey);
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( ok )
    return PyBytes_FromStringAndSize((const char *) bytes.begin(), bytes.size());
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
PyObject *py_reg_write_binary(const char *name, PyObject *py_bytes, const char *subkey = nullptr)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( PyBytes_Check(py_bytes) )
  {
    char *py_bytes_raw = nullptr;
    Py_ssize_t py_size = 0;
    PyBytes_AsStringAndSize(py_bytes, &py_bytes_raw, &py_size);
    bytevec_t bytes;
    bytes.append(py_bytes_raw, py_size);
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    reg_write_binary(name, bytes.begin(), bytes.size(), subkey);
    SWIG_PYTHON_THREAD_END_ALLOW;
    Py_RETURN_NONE;
  }
  else
  {
    PyErr_SetString(PyExc_ValueError, "Bytes string expected!");
    return nullptr;
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
