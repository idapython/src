#ifndef __PY_TYPEINF__
#define __PY_TYPEINF__

//<inline(py_typeinf)>
//-------------------------------------------------------------------------
PyObject *idc_parse_decl(til_t *ti, const char *decl, int flags)
{
  tinfo_t tif;
  qstring name;
  qtype fields, type;
  bool ok = parse_decl(&tif, &name, ti, decl, flags);
  if ( ok )
    ok = tif.serialize(&type, &fields, nullptr, SUDT_FAST);

  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ok )
    return Py_BuildValue("(s" PY_BV_TYPE PY_BV_FIELDS ")",
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
    @param ti: Type info library. 'None' can be passed.
    @param tp: serialized type byte string
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
  if ( PyBytes_Check(tp) )
  {
    // To avoid release of 'data' during Py_BEGIN|END_ALLOW_THREADS section.
    borref_t tpref(tp);
    const type_t *data = (type_t *)PyBytes_AsString(tp);
    size_t sz;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    tinfo_t tif;
    tif.deserialize(ti, &data, nullptr, nullptr);
    sz = tif.get_size();
    SWIG_PYTHON_THREAD_END_ALLOW;
    if ( sz != BADSIZE )
      return PyInt_FromLong(sz);
    Py_RETURN_NONE;
  }
  else
  {
    PyErr_SetString(PyExc_ValueError, "serialized type byte sequence expected!");
    return nullptr;
  }
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def apply_type(ti, ea, tp_name, py_type, py_fields, flags):
    """
    Apply the specified type to the address
    @param ti: Type info library. 'None' can be used.
    @param py_type: type string
    @param py_fields: fields string (may be empty or None)
    @param ea: the address of the object
    @param flags: combination of TINFO_... constants or 0
    @return: Boolean
    """
    pass
#</pydoc>
*/
static bool py_apply_type(
        til_t *ti,
        const type_t *type,
        const p_list *fields,
        ea_t ea,
        int flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  struc_t *sptr;
  member_t *mptr = get_member_by_id(ea, &sptr);
  if ( type == nullptr || type[0] == '\0' )
  {
    if ( mptr != nullptr )
    {
      rc = mptr->has_ti();
      if ( rc )
        del_member_tinfo(sptr, mptr);
    }
    else
    {
      rc = has_ti(ea);
      if ( rc )
        del_tinfo(ea);
    }
  }
  else
  {
    tinfo_t tif;
    rc = tif.deserialize(ti, &type, &fields, nullptr);
    if ( rc )
    {
      if ( mptr != nullptr )
        rc = set_member_tinfo(sptr, mptr, 0, tif, 0) > SMT_FAILED;
      else
        rc = apply_tinfo(ea, tif, flags);
    }
  }
  SWIG_PYTHON_THREAD_END_ALLOW;
  return rc;
}

//-------------------------------------------------------------------------
/*
header: typeinf.hpp
#<pydoc>
def get_arg_addrs(caller):
    """
    Retrieve addresses of argument initialization instructions

    @param caller: the address of the call instruction
    @return: list of instruction addresses
    """
    pass
#</pydoc>
*/
PyObject *py_get_arg_addrs(ea_t caller)
{
  eavec_t addrs;
  if ( !get_arg_addrs(&addrs, caller) )
    Py_RETURN_NONE;
  int n = addrs.size();
  PyObject *result = PyList_New(n);
  for ( size_t i = 0; i < n; ++i )
    PyList_SetItem(result, i, Py_BuildValue(PY_BV_EA, bvea_t(addrs[i])));
  return result;
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
        const type_t *type,
        const p_list *fields,
        ea_t ea,
        int pio_flags = 0)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  idc_value_t idc_obj;
  error_t err;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t tif;
  tif.deserialize(ti, &type, &fields);
  err = unpack_idcobj_from_idb(
      &idc_obj,
      tif,
      ea,
      nullptr,
      pio_flags);
  SWIG_PYTHON_THREAD_END_ALLOW;

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
    @param ti: Type info. 'None' can be passed.
    @param tp: type string
    @param fields: fields string (may be empty or None)
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
        const type_t *type,
        const p_list *fields,
        const bytevec_t &bytes,
        int pio_flags = 0)
{
  idc_value_t idc_obj;
  error_t err;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t tif;
  tif.deserialize(ti, &type, &fields);
  err = unpack_idcobj_from_bv(
      &idc_obj,
      tif,
      bytes,
      pio_flags);
  SWIG_PYTHON_THREAD_END_ALLOW;

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
    @param ti: Type info. 'None' can be passed.
    @param tp: type string
    @param fields: fields string (may be empty or None)
    @param ea: ea to be used while packing
    @param pio_flags: flags used while unpacking
    """
    pass
#</pydoc>
*/
PyObject *py_pack_object_to_idb(
        PyObject *py_obj,
        til_t *ti,
        const type_t *type,
        const p_list *fields,
        ea_t ea,
        int pio_flags = 0)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  borref_t py_obj_ref(py_obj);
  if ( !pyvar_to_idcvar_or_error(py_obj_ref, &idc_obj) )
    return nullptr;

  // Pack
  // error_t err;
  error_t err;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t tif;
  tif.deserialize(ti, &type, &fields);
  err = pack_idcobj_to_idb(&idc_obj, tif, ea, pio_flags);
  SWIG_PYTHON_THREAD_END_ALLOW;
  return PyInt_FromLong(err);
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def pack_object_to_bv(obj, ti, tp, fields, base_ea, pio_flags = 0):
    """
    Packs a typed object to a string
    @param ti: Type info. 'None' can be passed.
    @param tp: type string
    @param fields: fields string (may be empty or None)
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
        const type_t *type,
        const p_list *fields,
        ea_t base_ea,
        int pio_flags=0)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  borref_t py_obj_ref(py_obj);
  if ( !pyvar_to_idcvar_or_error(py_obj_ref, &idc_obj) )
    return nullptr;

  // Pack
  relobj_t bytes;
  error_t err;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t tif;
  tif.deserialize(ti, &type, &fields);
  err = pack_idcobj_to_bv(
    &idc_obj,
    tif,
    &bytes,
    nullptr,
    pio_flags);
  if ( err == eOk && !bytes.relocate(base_ea, inf_is_be()) )
    err = -1;
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( err == eOk )
    return Py_BuildValue("(i" PY_BV_BYTES "#)", 1, bytes.begin(), (Py_ssize_t) bytes.size());
  else
    return Py_BuildValue("(ii)", 0, err);
}

//-------------------------------------------------------------------------
/* Parse types from a string or file. See ParseTypes() in idc.py */
#define PT_FILE 0x00010000
int idc_parse_types(const char *input, int flags)
{
  int hti = ((flags >> 4) & 7) << HTI_PAK_SHIFT;

  if ( (flags & PT_FILE) != 0 )
  {
    hti |= HTI_FIL;
    flags &= ~PT_FILE;
  }

  return parse_decls(nullptr, input, (flags & PT_SIL) == 0 ? msg : nullptr, hti);
}

//-------------------------------------------------------------------------
PyObject *py_idc_get_type_raw(ea_t ea)
{
  tinfo_t tif;
  qtype type, fields;
  bool ok = get_tinfo(&tif, ea);
  if ( ok )
    ok = tif.serialize(&type, &fields, nullptr, SUDT_FAST);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ok )
    return Py_BuildValue("(" PY_BV_TYPE PY_BV_FIELDS ")", (char *)type.c_str(), (char *)fields.c_str());
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
PyObject *py_idc_get_local_type_raw(int ordinal)
{
  const type_t *type;
  const p_list *fields;
  bool ok = get_numbered_type(nullptr, ordinal, &type, &fields);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ok )
    return Py_BuildValue("(" PY_BV_TYPE PY_BV_FIELDS ")", (char *)type, (char *)fields);
  Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
char *idc_guess_type(ea_t ea, char *buf, size_t bufsize)
{
  tinfo_t tif;
  if ( guess_tinfo(&tif, ea) )
  {
    qstring out;
    if ( tif.print(&out) )
      return qstrncpy(buf, out.begin(), bufsize);
  }
  return nullptr;
}

//-------------------------------------------------------------------------
char *idc_get_type(ea_t ea, char *buf, size_t bufsize)
{
  tinfo_t tif;
  if ( get_tinfo(&tif, ea) )
  {
    qstring out;
    if ( tif.print(&out) )
    {
      qstrncpy(buf, out.c_str(), bufsize);
      return buf;
    }
  }
  return nullptr;
}

//-------------------------------------------------------------------------
int idc_set_local_type(int ordinal, const char *dcl, int flags)
{
  if ( dcl == nullptr || dcl[0] == '\0' )
  {
    if ( !del_numbered_type(nullptr, ordinal) )
      return 0;
  }
  else
  {
    tinfo_t tif;
    qstring name;
    if ( !parse_decl(&tif, &name, nullptr, dcl, flags) )
      return 0;

    if ( ordinal <= 0 )
    {
      if ( !name.empty() )
        ordinal = get_type_ordinal(nullptr, name.begin());

      if ( ordinal <= 0 )
        ordinal = alloc_type_ordinal(nullptr);
    }

    if ( tif.set_numbered_type(nullptr, ordinal, 0, name.c_str()) != TERR_OK )
      return 0;
  }
  return ordinal;
}

//-------------------------------------------------------------------------
int idc_get_local_type(int ordinal, int flags, char *buf, size_t bufsize)
{
  tinfo_t tif;
  if ( !tif.get_numbered_type(nullptr, ordinal) )
    return false;

  qstring res;
  const char *name = get_numbered_type_name(nullptr, ordinal);
  if ( !tif.print(&res, name, flags, 2, 40) )
    return false;

  qstrncpy(buf, res.begin(), bufsize);
  return true;
}

//-------------------------------------------------------------------------
PyObject *idc_print_type(
        const type_t *type,
        const p_list *fields,
        const char *name,
        int flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring res;
  bool ok;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t tif;
  ok = tif.deserialize(nullptr, &type, &fields, nullptr)
    && tif.print(&res, name, flags, 2, 40);
  SWIG_PYTHON_THREAD_END_ALLOW;
  if ( ok )
    return PyUnicode_FromString(res.begin());
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
char idc_get_local_type_name(int ordinal, char *buf, size_t bufsize)
{
  const char *name = get_numbered_type_name(nullptr, ordinal);
  if ( name == nullptr )
    return false;

  qstrncpy(buf, name, bufsize);
  return true;
}

//-------------------------------------------------------------------------
/*
#<pydoc>
def get_named_type(til, name, ntf_flags):
    """
    Get a type data by its name.
    @param til: the type library
    @param name: the type name
    @param ntf_flags: a combination of NTF_* constants
    @return:
        None on failure
        tuple(code, type_str, fields_str, cmt, field_cmts, sclass, value) on success
    """
    pass
#</pydoc>
*/
PyObject *py_get_named_type(const til_t *til, const char *name, int ntf_flags)
{
  const type_t *type = nullptr;
  const p_list *fields = nullptr, *field_cmts = nullptr;
  const char *cmt = nullptr;
  sclass_t sclass = SC_UNK;
  uint64 value = 0;
  int code = get_named_type(til, name, ntf_flags, &type, &fields, &cmt, &field_cmts, &sclass, (uint32 *) &value);
  if ( code == 0 )
    Py_RETURN_NONE;
  PyObject *py_value = (ntf_flags & NTF_64BIT) != 0
                     ? PyLong_FromUnsignedLongLong(value)
                     : PyLong_FromUnsignedLong(long(value));
  return Py_BuildValue("(i" PY_BV_TYPE PY_BV_FIELDS "s" PY_BV_FIELDCMTS "iN)",
                       code, type, fields, cmt, field_cmts, sclass, py_value);
}

//-------------------------------------------------------------------------
PyObject *py_get_named_type64(const til_t *til, const char *name, int ntf_flags)
{
  return py_get_named_type(til, name, ntf_flags | NTF_64BIT);
}

//-------------------------------------------------------------------------
PyObject *py_print_decls(text_sink_t &printer, til_t *til, PyObject *py_ordinals, uint32 flags)
{
  if ( !PyList_Check(py_ordinals) )
  {
    PyErr_SetString(PyExc_ValueError, "'ordinals' must be a list");
    return nullptr;
  }

  Py_ssize_t nords = PyList_Size(py_ordinals);
  ordvec_t ordinals;
  ordinals.reserve(size_t(nords));
  for ( Py_ssize_t i = 0; i < nords; ++i )
  {
    borref_t item(PyList_GetItem(py_ordinals, i));
    if ( !item || !PyLong_Check(item.o) )
    {
      qstring msg;
      msg.sprnt("ordinals[%d] is not a valid value", int(i));
      PyErr_SetString(PyExc_ValueError, msg.begin());
      return nullptr;
    }
    uint32 ord = PyLong_AsLong(item.o);
    ordinals.push_back(ord);
  }
  return PyLong_FromLong(print_decls(printer, til, ordinals.empty() ? nullptr : &ordinals, flags));
}

//-------------------------------------------------------------------------
PyObject *py_remove_tinfo_pointer(tinfo_t *tif, const char *name, const til_t *til)
{
  const char **pname = name == nullptr ? nullptr : &name;
  bool rc = remove_tinfo_pointer(tif, pname, til);
  return Py_BuildValue("(Os)", PyBool_FromLong(rc), pname != nullptr ? *pname : nullptr);
}

//-------------------------------------------------------------------------
static PyObject *py_get_numbered_type(const til_t *til, uint32 ordinal)
{
  const type_t *type;
  const p_list *fields;
  const char *cmt;
  const p_list *fieldcmts;
  sclass_t sclass;
  if ( get_numbered_type(til, ordinal, &type, &fields, &cmt, &fieldcmts, &sclass) )
    return Py_BuildValue("(" PY_BV_TYPE PY_BV_FIELDS "s" PY_BV_FIELDCMTS "i)", type, fields, cmt, fieldcmts, sclass);
  else
    Py_RETURN_NONE;
}

//</inline(py_typeinf)>

//<code(py_typeinf)>
//-------------------------------------------------------------------------
// tuple(type_str, fields_str, field_cmts) on success
static PyObject *py_tinfo_t_serialize(
        const tinfo_t *tif,
        int sudt_flags)
{
  qtype type, fields, fldcmts;
  if ( !tif->serialize(&type, &fields, &fldcmts, sudt_flags) )
    Py_RETURN_NONE;
  PyObject *tuple = PyTuple_New(3);
  int ctr = 0;
#define ADD(Thing)                                              \
  do                                                            \
  {                                                             \
    PyObject *o = Py_None;                                      \
    if ( (Thing).empty() )                                      \
      Py_INCREF(Py_None);                                       \
    else                                                        \
      o = PyBytes_FromString((const char *) (Thing).begin());   \
    PyTuple_SetItem(tuple, ctr, o);                             \
    ++ctr;                                                      \
  } while ( false )
  ADD(type);
  ADD(fields);
  ADD(fldcmts);
#undef ADD
  return tuple;
}
//</code(py_typeinf)>


#endif
