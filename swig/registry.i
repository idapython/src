
%ignore reg_bin_op;
%ignore reg_str_op;
%ignore reg_int_op;
%ignore _RVN_;
%ignore REG_VAL_NAME;
%ignore REG_BOOL_FUNC;
%ignore REG_INT_FUNC;
%ignore MAX_HISTORY_FILES_DEF;
%ignore regkey_history;
%ignore max_history_files;
%ignore regget_history;
%ignore reg_update_history;
%ignore reg_history_size_truncate;

%ignore reg_read_string;
%rename (reg_read_string) py_reg_read_string;

%ignore reg_data_type;
%rename (reg_data_type) py_reg_data_type;

%ignore reg_read_binary;
%rename (reg_read_binary) py_reg_read_binary;
%ignore reg_write_binary;
%rename (reg_write_binary) py_reg_write_binary;

%ignore reg_read_binary_part;

/* inline bool reg_subkey_subkeys(qstrvec_t *out, const char *name) */
%ignore reg_subkey_subkeys;
%rename (reg_subkey_subkeys) py_reg_subkey_subkeys;
%ignore reg_subkey_values;
%rename (reg_subkey_values) py_reg_subkey_values;
%ignore reg_subkey_children;

%{
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
        PyList_SET_ITEM(result, i, PyString_FromString(children[i].c_str()));
  }
  Py_END_ALLOW_THREADS;
  if ( result == NULL )
    Py_RETURN_NONE;
  else
    return result;
}
//</code(py_registry)>
%}

%inline %{
//<inline(py_registry)>
//-------------------------------------------------------------------------
PyObject *py_reg_read_string(const char *name, const char *subkey = NULL, const char *def = NULL)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  char utf8[MAXSTR * 10];
  bool ok;
  Py_BEGIN_ALLOW_THREADS;
  if ( def == NULL )
  {
    ok = reg_read_string(name, utf8, sizeof(utf8), subkey);
  }
  else
  {
    reg_read_string(name, sizeof(utf8), utf8, def, subkey);
    ok = true;
  }
  Py_END_ALLOW_THREADS;
  return PyString_FromString(ok ? utf8 : "");
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
    return PyString_FromStringAndSize((const char *) bytes.begin(), bytes.size());
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
void py_reg_write_binary(const char *name, PyObject *py_bytes, const char *subkey = NULL)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( PyString_Check(py_bytes) )
  {
    char *py_bytes_raw = NULL;
    Py_ssize_t py_size = 0;
    PyString_AsStringAndSize(py_bytes, &py_bytes_raw, &py_size);
    bytevec_t bytes;
    bytes.append(py_bytes_raw, py_size);
    Py_BEGIN_ALLOW_THREADS;
    reg_write_binary(name, bytes.begin(), bytes.size(), subkey);
    Py_END_ALLOW_THREADS;
  }
  else
  {
    PyErr_SetString(PyExc_ValueError, "Bytes string expected!");
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
%}

%include "registry.hpp"
