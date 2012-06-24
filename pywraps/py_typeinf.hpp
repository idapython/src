#ifndef __PY_TYPEINF__
#define __PY_TYPEINF__

//<inline(py_typeinf)>
//-------------------------------------------------------------------------
PyObject *idc_parse_decl(til_t *ti, const char *decl, int flags)
{
  qtype fields, type;
  qstring name;
  bool ok = parse_decl(ti, decl, &name, &type, &fields, flags);
  if ( !ok )
    Py_RETURN_NONE;

  return Py_BuildValue("(sss)",
    name.c_str(),
    (char *)type.c_str(),
    (char *)fields.c_str());
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_type_size0(ti, tp):
    """
    Returns the size of a type
    @param ti: Type info. 'idaapi.cvar.idati' can be passed.
    @param tp: type string
    @return:
        - None on failure
        - The size of the type
    """
    pass
#</pydoc>
*/
PyObject *py_get_type_size0(const til_t *ti, PyObject *tp)
{
  if ( !PyString_Check(tp) )
  {
    PyErr_SetString(PyExc_ValueError, "String expected!");
    return NULL;
  }

  size_t sz = get_type_size0(ti, (type_t *)PyString_AsString(tp));
  if ( sz == BADSIZE )
    Py_RETURN_NONE;

  return PyInt_FromLong(sz);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def print_type(ea, on_line):
    """
    Returns the type of an item
    @return:
        - None on failure
        - The type string with a semicolon. Can be used directly with idc.SetType()
    """
    pass
#</pydoc>
*/
static PyObject *py_print_type(ea_t ea, bool one_line)
{
  char buf[MAXSTR];
  if ( print_type(ea, buf, sizeof(buf), one_line) )
  {
    qstrncat(buf, ";", sizeof(buf));
    return PyString_FromString(buf);
  }
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def py_unpack_object_from_idb(ti, tp, fields, ea, pio_flags = 0):
    """
    Unpacks from the database at 'ea' to an object.
    Please refer to unpack_object_from_bv()
    """
    pass
#</pydoc>
*/
PyObject *py_unpack_object_from_idb(
  til_t *ti,
  PyObject *py_type,
  PyObject *py_fields,
  ea_t ea,
  int pio_flags = 0)
{
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) )
  {
    PyErr_SetString(PyExc_ValueError, "Typestring must be passed!");
    return NULL;
  }

  // Unpack
  type_t *type   = (type_t *) PyString_AsString(py_type);
  p_list *fields = (p_list *) PyString_AsString(py_fields);
  idc_value_t idc_obj;
  error_t err = unpack_object_from_idb(
      &idc_obj,
      ti,
      type,
      fields,
      ea,
      NULL,
      pio_flags);

  // Unpacking failed?
  if ( err != eOk )
    return Py_BuildValue("(ii)", 0, err);

  // Convert
  PyObject *py_ret(NULL);
  err = idcvar_to_pyvar(idc_obj, &py_ret);

  // Conversion failed?
  if ( err != CIP_OK )
    return Py_BuildValue("(ii)", 0, err);

  PyObject *py_result = Py_BuildValue("(iO)", 1, py_ret);
  Py_DECREF(py_ret);
  return py_result;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def unpack_object_from_bv(ti, tp, fields, bytes, pio_flags = 0):
    """
    Unpacks a buffer into an object.
    Returns the error_t returned by idaapi.pack_object_to_idb
    @param ti: Type info. 'idaapi.cvar.idati' can be passed.
    @param tp: type string
    @param fields: type fields
    @param bytes: the bytes to unpack
    @param pio_flags: flags used while unpacking
    @return:
        - tuple(0, err) on failure
        - tuple(1, obj) on success
    """
    pass
#</pydoc>
*/
PyObject *py_unpack_object_from_bv(
  til_t *ti,
  PyObject *py_type,
  PyObject *py_fields,
  PyObject *py_bytes,
  int pio_flags = 0)
{
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) && !PyString_Check(py_bytes) )
  {
    PyErr_SetString(PyExc_ValueError, "Incorrect argument type!");
    return NULL;
  }

  // Get type strings
  type_t *type   = (type_t *) PyString_AsString(py_type);
  p_list *fields = (p_list *) PyString_AsString(py_fields);

  // Make a byte vector
  bytevec_t bytes;
  bytes.resize(PyString_Size(py_bytes));
  memcpy(bytes.begin(), PyString_AsString(py_bytes), bytes.size());

  idc_value_t idc_obj;
  error_t err = unpack_object_from_bv(
      &idc_obj,
      ti,
      type,
      fields,
      bytes,
      pio_flags);

  // Unpacking failed?
  if ( err != eOk )
    return Py_BuildValue("(ii)", 0, err);

  // Convert
  PyObject *py_ret(NULL);
  err = idcvar_to_pyvar(idc_obj, &py_ret);

  // Conversion failed?
  if ( err != CIP_OK )
    return Py_BuildValue("(ii)", 0, err);

  PyObject *py_result = Py_BuildValue("(iO)", 1, py_ret);
  Py_DECREF(py_ret);
  return py_result;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def pack_object_to_idb(obj, ti, tp, fields, ea, pio_flags = 0):
    """
    Write a typed object to the database.
    Raises an exception if wrong parameters were passed or conversion fails
    Returns the error_t returned by idaapi.pack_object_to_idb
    @param ti: Type info. 'idaapi.cvar.idati' can be passed.
    @param tp: type string
    @param fields: type fields
    @param ea: ea to be used while packing
    @param pio_flags: flags used while unpacking
    """
    pass
#</pydoc>
*/
PyObject *py_pack_object_to_idb(
  PyObject *py_obj,
  til_t *ti,
  PyObject *py_type,
  PyObject *py_fields,
  ea_t ea,
  int pio_flags = 0)
{
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) )
  {
    PyErr_SetString(PyExc_ValueError, "Typestring must be passed!");
    return NULL;
  }

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  if ( !convert_pyobj_to_idc_exc(py_obj, &idc_obj) )
    return NULL;

  // Get type strings
  type_t *type   = (type_t *) PyString_AsString(py_type);
  p_list *fields = (p_list *) PyString_AsString(py_fields);

  // Pack
  error_t err = pack_object_to_idb(&idc_obj, ti, type, fields, ea, pio_flags);
  return PyInt_FromLong(err);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def pack_object_to_bv(obj, ti, tp, fields, base_ea, pio_flags = 0):
    """
    Packs a typed object to a string
    @param ti: Type info. 'idaapi.cvar.idati' can be passed.
    @param tp: type string
    @param fields: type fields
    @param base_ea: base ea used to relocate the pointers in the packed object
    @param pio_flags: flags used while unpacking
    @return:
        tuple(0, err_code) on failure
        tuple(1, packed_buf) on success
    """
    pass
#</pydoc>
*/
// Returns a tuple(Boolean, PackedBuffer or Error Code)
PyObject *py_pack_object_to_bv(
  PyObject *py_obj,
  til_t *ti,
  PyObject *py_type,
  PyObject *py_fields,
  ea_t base_ea,
  int pio_flags=0)
{
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) )
  {
    PyErr_SetString(PyExc_ValueError, "Typestring must be passed!");
    return NULL;
  }

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  if ( !convert_pyobj_to_idc_exc(py_obj, &idc_obj) )
    return NULL;

  // Get type strings
  type_t *type   = (type_t *) PyString_AsString(py_type);
  p_list *fields = (p_list *) PyString_AsString(py_fields);

  // Pack
  relobj_t bytes;
  error_t err = pack_object_to_bv(
    &idc_obj,
    ti,
    type,
    fields,
    &bytes,
    NULL,
    pio_flags);
  do
  {
    if ( err != eOk )
      break;
    if ( !bytes.relocate(base_ea, inf.mf) )
    {
      err = -1;
      break;
    }
    return Py_BuildValue("(is#)", 1, bytes.begin(), bytes.size());
  } while ( false );
  return Py_BuildValue("(ii)", 0, err);
}
//</inline(py_typeinf)>

#endif
