#ifndef __PY_TYPEINF__
#define __PY_TYPEINF__

//<inline(py_typeinf)>
//-------------------------------------------------------------------------
PyObject *idc_parse_decl(til_t *ti, const char *decl, int flags)
{
  tinfo_t tif;
  qstring name;
  qtype fields, type;
  bool ok = parse_decl2(ti, decl, &name, &tif, flags);
  if ( ok )
    ok = tif.serialize(&type, &fields, NULL, SUDT_FAST);

  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ok )
    return Py_BuildValue("(sss)",
                         name.c_str(),
                         (char *)type.c_str(),
                         (char *)fields.c_str());
  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def calc_type_size(ti, tp):
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
PyObject *py_calc_type_size(const til_t *ti, PyObject *tp)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( PyString_Check(tp) )
  {
    // To avoid release of 'data' during Py_BEGIN|END_ALLOW_THREADS section.
    borref_t tpref(tp);
    const type_t *data = (type_t *)PyString_AsString(tp);
    size_t sz;
    Py_BEGIN_ALLOW_THREADS;
    tinfo_t tif;
    tif.deserialize(ti, &data, NULL, NULL);
    sz = tif.get_size();
    Py_END_ALLOW_THREADS;
    if ( sz != BADSIZE )
      return PyInt_FromLong(sz);
    Py_RETURN_NONE;
  }
  else
  {
    PyErr_SetString(PyExc_ValueError, "String expected!");
    return NULL;
  }
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def apply_type(ti, ea, tp_name, py_type, py_fields, flags)
    """
    Apply the specified type to the address
    @param ti: Type info. 'idaapi.cvar.idati' can be passed.
    @param py_type: type string
    @param py_fields: type fields
    @param ea: the address of the object
    @param flags: combination of TINFO_... constants or 0
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_apply_type(til_t *ti, PyObject *py_type, PyObject *py_fields, ea_t ea, int flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) )
  {
    PyErr_SetString(PyExc_ValueError, "Typestring must be passed!");
    return NULL;
  }
  const type_t *type   = (const type_t *) PyString_AsString(py_type);
  const p_list *fields = (const p_list *) PyString_AsString(py_fields);
  bool rc;
  Py_BEGIN_ALLOW_THREADS;
  tinfo_t tif;
  rc = tif.deserialize(ti, &type, &fields, NULL) && apply_tinfo2(ea, tif, flags);
  Py_END_ALLOW_THREADS;
  return rc;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def print_type(ea, one_line):
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
  char buf[64*MAXSTR];
  int flags = PRTYPE_SEMI | (one_line ? PRTYPE_1LINE : PRTYPE_MULTI);
  bool ok = print_type2(ea, buf, sizeof(buf), one_line ? PRTYPE_1LINE : PRTYPE_MULTI);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ok )
    return PyString_FromString(buf);
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
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) )
  {
    PyErr_SetString(PyExc_ValueError, "Typestring must be passed!");
    return NULL;
  }

  // To avoid release of 'type'/'fields' during Py_BEGIN|END_ALLOW_THREADS section.
  borref_t py_type_ref(py_type);
  borref_t py_fields_ref(py_fields);

  // Unpack
  type_t *type   = (type_t *) PyString_AsString(py_type);
  p_list *fields = (p_list *) PyString_AsString(py_fields);
  idc_value_t idc_obj;
  error_t err;
  Py_BEGIN_ALLOW_THREADS;
  err = unpack_object_from_idb(
      &idc_obj,
      ti,
      type,
      fields,
      ea,
      NULL,
      pio_flags);
  Py_END_ALLOW_THREADS;

  // Unpacking failed?
  if ( err != eOk )
    return Py_BuildValue("(ii)", 0, err);

  // Convert
  ref_t py_ret;
  err = idcvar_to_pyvar(idc_obj, &py_ret);

  // Conversion failed?
  if ( err != CIP_OK )
    return Py_BuildValue("(ii)", 0, err);
  else
    return Py_BuildValue("(iO)", 1, py_ret.o);
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
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) && !PyString_Check(py_bytes) )
  {
    PyErr_SetString(PyExc_ValueError, "Incorrect argument type!");
    return NULL;
  }

  // To avoid release of 'type'/'fields' during Py_BEGIN|END_ALLOW_THREADS section.
  borref_t py_type_ref(py_type);
  borref_t py_fields_ref(py_fields);

  // Get type strings
  type_t *type   = (type_t *) PyString_AsString(py_type);
  p_list *fields = (p_list *) PyString_AsString(py_fields);

  // Make a byte vector
  bytevec_t bytes;
  bytes.resize(PyString_Size(py_bytes));
  memcpy(bytes.begin(), PyString_AsString(py_bytes), bytes.size());

  idc_value_t idc_obj;
  error_t err;
  Py_BEGIN_ALLOW_THREADS;
  err = unpack_object_from_bv(
      &idc_obj,
      ti,
      type,
      fields,
      bytes,
      pio_flags);
  Py_END_ALLOW_THREADS;

  // Unpacking failed?
  if ( err != eOk )
    return Py_BuildValue("(ii)", 0, err);

  // Convert
  ref_t py_ret;
  err = idcvar_to_pyvar(idc_obj, &py_ret);

  // Conversion failed?
  if ( err != CIP_OK )
    return Py_BuildValue("(ii)", 0, err);

  return Py_BuildValue("(iO)", 1, py_ret.o);
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
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) )
  {
    PyErr_SetString(PyExc_ValueError, "Typestring must be passed!");
    return NULL;
  }

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  borref_t py_obj_ref(py_obj);
  if ( !pyvar_to_idcvar_or_error(py_obj_ref, &idc_obj) )
    return NULL;

  // To avoid release of 'type'/'fields' during Py_BEGIN|END_ALLOW_THREADS section.
  borref_t py_type_ref(py_type);
  borref_t py_fields_ref(py_fields);

  // Get type strings
  type_t *type   = (type_t *)PyString_AsString(py_type);
  p_list *fields = (p_list *)PyString_AsString(py_fields);

  // Pack
  // error_t err;
  error_t err;
  Py_BEGIN_ALLOW_THREADS;
  err = pack_object_to_idb(&idc_obj, ti, type, fields, ea, pio_flags);
  Py_END_ALLOW_THREADS;
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
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) )
  {
    PyErr_SetString(PyExc_ValueError, "Typestring must be passed!");
    return NULL;
  }

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  borref_t py_obj_ref(py_obj);
  if ( !pyvar_to_idcvar_or_error(py_obj_ref, &idc_obj) )
    return NULL;

  // To avoid release of 'type'/'fields' during Py_BEGIN|END_ALLOW_THREADS section.
  borref_t py_type_ref(py_type);
  borref_t py_fields_ref(py_fields);

  // Get type strings
  type_t *type   = (type_t *)PyString_AsString(py_type);
  p_list *fields = (p_list *)PyString_AsString(py_fields);

  // Pack
  relobj_t bytes;
  error_t err;
  Py_BEGIN_ALLOW_THREADS;
  err = pack_object_to_bv(
    &idc_obj,
    ti,
    type,
    fields,
    &bytes,
    NULL,
    pio_flags);
  if ( err == eOk && !bytes.relocate(base_ea, inf.mf) )
      err = -1;
  Py_END_ALLOW_THREADS;
  if ( err == eOk )
    return Py_BuildValue("(is#)", 1, bytes.begin(), bytes.size());
  else
    return Py_BuildValue("(ii)", 0, err);
}

//-------------------------------------------------------------------------
/* Parse types from a string or file. See ParseTypes() in idc.py */
int idc_parse_types(const char *input, int flags)
{
  int hti = ((flags >> 4) & 7) << HTI_PAK_SHIFT;

  if ((flags & 1) != 0)
      hti |= HTI_FIL;

  return parse_decls(idati, input, (flags & 2) == 0 ? msg : NULL, hti);
}

//-------------------------------------------------------------------------
PyObject *py_idc_get_type_raw(ea_t ea)
{
  qtype type, fields;
  bool ok = get_tinfo(ea, &type, &fields);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ok )
    return Py_BuildValue("(ss)", (char *)type.c_str(), (char *)fields.c_str());
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
PyObject *py_idc_get_local_type_raw(int ordinal)
{
  const type_t *type;
  const p_list *fields;
  bool ok = get_numbered_type(idati, ordinal, &type, &fields);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ok )
    return Py_BuildValue("(ss)", (char *)type, (char *)fields);
  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
char *idc_guess_type(ea_t ea, char *buf, size_t bufsize)
{
  tinfo_t tif;
  if ( guess_tinfo2(ea, &tif) )
  {
    qstring out;
    if ( tif.print(&out) )
      return qstrncpy(buf, out.begin(), bufsize);
  }
  return NULL;
}

//-------------------------------------------------------------------------
char *idc_get_type(ea_t ea, char *buf, size_t bufsize)
{
  tinfo_t tif;
  if ( get_tinfo2(ea, &tif) )
  {
    qstring out;
    if ( tif.print(&out) )
    {
      qstrncpy(buf, out.c_str(), bufsize);
      return buf;
    }
  }
  return NULL;
}

//-------------------------------------------------------------------------
int idc_set_local_type(int ordinal, const char *dcl, int flags)
{
  if (dcl == NULL || dcl[0] == '\0')
  {
    if ( !del_numbered_type(idati, ordinal) )
        return 0;
  }
  else
  {
    tinfo_t tif;
    qstring name;
    if ( !parse_decl2(idati, dcl, &name, &tif, flags) )
      return 0;

    if ( ordinal <= 0 )
    {
      if ( !name.empty() )
        ordinal = get_type_ordinal(idati, name.begin());

      if ( ordinal <= 0 )
        ordinal = alloc_type_ordinal(idati);
    }

    if ( tif.set_numbered_type(idati, ordinal, 0, name.c_str()) != TERR_OK )
      return 0;
  }
  return ordinal;
}

//-------------------------------------------------------------------------
int idc_get_local_type(int ordinal, int flags, char *buf, size_t maxsize)
{
  tinfo_t tif;
  if ( !tif.get_numbered_type(idati, ordinal) )
  {
    buf[0] = 0;
    return false;
  }

  qstring res;
  const char *name = get_numbered_type_name(idati, ordinal);
  if ( !tif.print(&res, name, flags, 2, 40) )
  {
    buf[0] = 0;
    return false;
  }

  qstrncpy(buf, res.begin(), maxsize);
  return true;
}

//-------------------------------------------------------------------------
PyObject *idc_print_type(PyObject *py_type, PyObject *py_fields, const char *name, int flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( !PyString_Check(py_type) && !PyString_Check(py_fields) )
  {
    PyErr_SetString(PyExc_ValueError, "Typestring must be passed!");
    return NULL;
  }

  // To avoid release of 'type'/'fields' during Py_BEGIN|END_ALLOW_THREADS section.
  borref_t py_type_ref(py_type);
  borref_t py_fields_ref(py_fields);

  qstring res;
  const type_t *type   = (type_t *)PyString_AsString(py_type);
  const p_list *fields = (p_list *)PyString_AsString(py_fields);
  bool ok;
  Py_BEGIN_ALLOW_THREADS;
  tinfo_t tif;
  ok = tif.deserialize(idati, &type, &fields, NULL)
    && tif.print(&res, name, flags, 2, 40);
  Py_END_ALLOW_THREADS;
  if ( ok )
    return PyString_FromString(res.begin());
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
char idc_get_local_type_name(int ordinal, char *buf, size_t bufsize)
{
  const char *name = get_numbered_type_name(idati, ordinal);
  if ( name == NULL )
    return false;

  qstrncpy(buf, name, bufsize);
  return true;
}
//</inline(py_typeinf)>

//<code(py_typeinf)>
//-------------------------------------------------------------------------
// A set of tinfo_t objects that were created from IDAPython.
// This is necessary in order to clear all the "type details" that are
// associated, in the kernel, with the tinfo_t instances.
//
// Unfortunately the IDAPython plugin has to terminate _after_ the IDB is
// closed, but the "type details" must be cleared _before_ the IDB is closed.
static qvector<tinfo_t*> python_tinfos;
void til_clear_python_tinfo_t_instances(void)
{
  // Pre-emptive strike: clear all the python-exposed tinfo_t instances: if that
  // were not done here, ~tinfo_t() calls happening as part of the python shutdown
  // process will try and clear() their details. ..but the kernel's til-related
  // functions will already have deleted those details at that point.
  for ( size_t i = 0, n = python_tinfos.size(); i < n; ++i )
    python_tinfos[i]->clear();
  // NOTE: Don't clear() the array of pointers. All the python-exposed tinfo_t
  // instances will be deleted through the python shutdown/ref-decrementing
  // process anyway (which will cause til_deregister_..() calls), and the
  // entries will be properly pulled out of the vector when that happens.
}

void til_register_python_tinfo_t_instance(tinfo_t *tif)
{
  // Let's add_unique() it, because every reference to an object's
  // tinfo_t property will end up trying to register it.
  python_tinfos.add_unique(tif);
}

void til_deregister_python_tinfo_t_instance(tinfo_t *tif)
{
  qvector<tinfo_t*>::iterator found = python_tinfos.find(tif);
  if ( found != python_tinfos.end() )
  {
    tif->clear();
    python_tinfos.erase(found);
  }
}

//</code(py_typeinf)>


#endif
