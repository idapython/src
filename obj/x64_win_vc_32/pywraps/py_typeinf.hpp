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
    @param ti: Type info. 'None' can be passed.
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
  if ( IDAPyStr_Check(tp) )
  {
    // To avoid release of 'data' during Py_BEGIN|END_ALLOW_THREADS section.
    borref_t tpref(tp);
    const type_t *data = (type_t *)IDAPyBytes_AsString(tp);
    size_t sz;
    Py_BEGIN_ALLOW_THREADS;
    tinfo_t tif;
    tif.deserialize(ti, &data, NULL, NULL);
    sz = tif.get_size();
    Py_END_ALLOW_THREADS;
    if ( sz != BADSIZE )
      return IDAPyInt_FromLong(sz);
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
        const bytevec_t &_type,
        const bytevec_t &_fields,
        ea_t ea,
        int flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  const type_t *type   = (const type_t *) _type.begin();
  const p_list *fields = (const p_list *) _fields.begin();
  bool rc;
  Py_BEGIN_ALLOW_THREADS;
  struc_t *sptr;
  member_t *mptr = get_member_by_id(ea, &sptr);
  if ( type == NULL || type[0] == '\0' )
  {
    if ( mptr != NULL )
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
    rc = tif.deserialize(ti, &type, &fields, NULL);
    if ( rc )
    {
      if ( mptr != NULL )
        rc = set_member_tinfo(sptr, mptr, 0, tif, 0) > SMT_FAILED;
      else
        rc = apply_tinfo(ea, tif, flags);
    }
  }
  Py_END_ALLOW_THREADS;
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
        const bytevec_t &_type,
        const bytevec_t &_fields,
        ea_t ea,
        int pio_flags = 0)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  const type_t *type   = (const type_t *) _type.begin();
  const p_list *fields = (const p_list *) _fields.begin();
  idc_value_t idc_obj;
  error_t err;
  Py_BEGIN_ALLOW_THREADS;
  tinfo_t tif;
  tif.deserialize(ti, &type, &fields);
  err = unpack_idcobj_from_idb(
      &idc_obj,
      tif,
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
        const bytevec_t &_type,
        const bytevec_t &_fields,
        const bytevec_t &bytes,
        int pio_flags = 0)
{
  const type_t *type   = (const type_t *) _type.begin();
  const p_list *fields = (const p_list *) _fields.begin();
  idc_value_t idc_obj;
  error_t err;
  Py_BEGIN_ALLOW_THREADS;
  tinfo_t tif;
  tif.deserialize(ti, &type, &fields);
  err = unpack_idcobj_from_bv(
      &idc_obj,
      tif,
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
        const bytevec_t &_type,
        const bytevec_t &_fields,
        ea_t ea,
        int pio_flags = 0)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  borref_t py_obj_ref(py_obj);
  if ( !pyvar_to_idcvar_or_error(py_obj_ref, &idc_obj) )
    return NULL;

  const type_t *type   = (const type_t *) _type.begin();
  const p_list *fields = (const p_list *) _fields.begin();

  // Pack
  // error_t err;
  error_t err;
  Py_BEGIN_ALLOW_THREADS;
  tinfo_t tif;
  tif.deserialize(ti, &type, &fields);
  err = pack_idcobj_to_idb(&idc_obj, tif, ea, pio_flags);
  Py_END_ALLOW_THREADS;
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
        const bytevec_t &_type,
        const bytevec_t &_fields,
        ea_t base_ea,
        int pio_flags=0)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  borref_t py_obj_ref(py_obj);
  if ( !pyvar_to_idcvar_or_error(py_obj_ref, &idc_obj) )
    return NULL;

  // Get type strings
  const type_t *type   = (const type_t *) _type.begin();
  const p_list *fields = (const p_list *) _fields.begin();

  // Pack
  relobj_t bytes;
  error_t err;
  Py_BEGIN_ALLOW_THREADS;
  tinfo_t tif;
  tif.deserialize(ti, &type, &fields);
  err = pack_idcobj_to_bv(
    &idc_obj,
    tif,
    &bytes,
    NULL,
    pio_flags);
  if ( err == eOk && !bytes.relocate(base_ea, inf.is_be()) )
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

  if ( (flags & 1) != 0 )
    hti |= HTI_FIL;

  return parse_decls(NULL, input, (flags & 2) == 0 ? msg : NULL, hti);
}

//-------------------------------------------------------------------------
PyObject *py_idc_get_type_raw(ea_t ea)
{
  tinfo_t tif;
  qtype type, fields;
  bool ok = get_tinfo(&tif, ea);
  if ( ok )
    ok = tif.serialize(&type, &fields, NULL, SUDT_FAST);
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
  bool ok = get_numbered_type(NULL, ordinal, &type, &fields);
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( ok )
    return Py_BuildValue("(ss)", (char *)type, (char *)fields);
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
  return NULL;
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
  return NULL;
}

//-------------------------------------------------------------------------
int idc_set_local_type(int ordinal, const char *dcl, int flags)
{
  if ( dcl == NULL || dcl[0] == '\0' )
  {
    if ( !del_numbered_type(NULL, ordinal) )
      return 0;
  }
  else
  {
    tinfo_t tif;
    qstring name;
    if ( !parse_decl(&tif, &name, NULL, dcl, flags) )
      return 0;

    if ( ordinal <= 0 )
    {
      if ( !name.empty() )
        ordinal = get_type_ordinal(NULL, name.begin());

      if ( ordinal <= 0 )
        ordinal = alloc_type_ordinal(NULL);
    }

    if ( tif.set_numbered_type(NULL, ordinal, 0, name.c_str()) != TERR_OK )
      return 0;
  }
  return ordinal;
}

//-------------------------------------------------------------------------
int idc_get_local_type(int ordinal, int flags, char *buf, size_t maxsize)
{
  tinfo_t tif;
  if ( !tif.get_numbered_type(NULL, ordinal) )
  {
    buf[0] = 0;
    return false;
  }

  qstring res;
  const char *name = get_numbered_type_name(NULL, ordinal);
  if ( !tif.print(&res, name, flags, 2, 40) )
  {
    buf[0] = 0;
    return false;
  }

  qstrncpy(buf, res.begin(), maxsize);
  return true;
}

//-------------------------------------------------------------------------
PyObject *idc_print_type(
        const bytevec_t &_type,
        const bytevec_t &_fields,
        const char *name,
        int flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  qstring res;
  const type_t *type   = (const type_t *) _type.begin();
  const p_list *fields = (const p_list *) _fields.begin();
  bool ok;
  Py_BEGIN_ALLOW_THREADS;
  tinfo_t tif;
  ok = tif.deserialize(NULL, &type, &fields, NULL)
    && tif.print(&res, name, flags, 2, 40);
  Py_END_ALLOW_THREADS;
  if ( ok )
    return IDAPyStr_FromUTF8(res.begin());
  else
    Py_RETURN_NONE;
}

//-------------------------------------------------------------------------
char idc_get_local_type_name(int ordinal, char *buf, size_t bufsize)
{
  const char *name = get_numbered_type_name(NULL, ordinal);
  if ( name == NULL )
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
  const type_t *type = NULL;
  const p_list *fields = NULL, *field_cmts = NULL;
  const char *cmt = NULL;
  sclass_t sclass = sc_unk;
  uint64 value = 0;
  int code = get_named_type(til, name, ntf_flags, &type, &fields, &cmt, &field_cmts, &sclass, (uint32 *) &value);
  if ( code == 0 )
    Py_RETURN_NONE;
  PyObject *tuple = PyTuple_New(7);
  int idx = 0;
#define ADD(Expr) PyTuple_SetItem(tuple, idx++, (Expr))
#define ADD_OR_NONE(Cond, Expr)                 \
  do                                            \
  {                                             \
    if ( Cond )                                 \
    {                                           \
      ADD(Expr);                                \
    }                                           \
    else                                        \
    {                                           \
      Py_INCREF(Py_None);                       \
      ADD(Py_None);                             \
    }                                           \
  } while ( false )

  ADD(IDAPyInt_FromLong(long(code)));
  ADD(IDAPyStr_FromUTF8((const char *) type));
  ADD_OR_NONE(fields != NULL, IDAPyStr_FromUTF8((const char *) fields));
  ADD_OR_NONE(cmt != NULL, IDAPyStr_FromUTF8(cmt));
  ADD_OR_NONE(field_cmts != NULL, IDAPyStr_FromUTF8((const char *) field_cmts));
  ADD(IDAPyInt_FromLong(long(sclass)));
  if ( (ntf_flags & NTF_64BIT) != 0 )
    ADD(PyLong_FromUnsignedLongLong(value));
  else
    ADD(PyLong_FromUnsignedLong(long(value)));
#undef ADD_OR_NONE
#undef ADD
  return tuple;
}

//-------------------------------------------------------------------------
PyObject *py_get_named_type64(const til_t *til, const char *name, int ntf_flags)
{
  return py_get_named_type(til, name, ntf_flags | NTF_64BIT);
}

//-------------------------------------------------------------------------
int py_print_decls(text_sink_t &printer, til_t *til, PyObject *py_ordinals, uint32 flags)
{
  if ( !PyList_Check(py_ordinals) )
  {
    PyErr_SetString(PyExc_ValueError, "'ordinals' must be a list");
    return 0;
  }

  Py_ssize_t nords = PyList_Size(py_ordinals);
  ordvec_t ordinals;
  ordinals.reserve(size_t(nords));
  for ( Py_ssize_t i = 0; i < nords; ++i )
  {
    borref_t item(PyList_GetItem(py_ordinals, i));
    if ( item == NULL
      || (!IDAPyInt_Check(item.o) && !PyLong_Check(item.o)) )
    {
      qstring msg;
      msg.sprnt("ordinals[%d] is not a valid value", int(i));
      PyErr_SetString(PyExc_ValueError, msg.begin());
      return 0;
    }
    uint32 ord = IDAPyInt_Check(item.o) ? IDAPyInt_AsLong(item.o) : PyLong_AsLong(item.o);
    ordinals.push_back(ord);
  }
  return print_decls(printer, til, ordinals.empty() ? NULL : &ordinals, flags);
}

//-------------------------------------------------------------------------
til_t *py_load_til(const char *name, const char *tildir)
{
  qstring errbuf;
  til_t *res = load_til(name, &errbuf, tildir);
  if ( res == NULL )
    PyErr_SetString(PyExc_RuntimeError, errbuf.c_str());
  return res;
}

//-------------------------------------------------------------------------
til_t *py_load_til_header(const char *tildir, const char *name)
{
  qstring errbuf;
  til_t *res = load_til_header(tildir, name, &errbuf);
  if ( res == NULL )
    PyErr_SetString(PyExc_RuntimeError, errbuf.c_str());
  return res;
}

#ifdef BC695
// dummy idati, to generate the cvar. We'll patch the code so
// it does retrieve the real idati through get_idati()
til_t *idati = NULL;
#endif

//-------------------------------------------------------------------------
PyObject *py_remove_tinfo_pointer(tinfo_t *tif, const char *name, const til_t *til)
{
  const char **pname = name == NULL ? NULL : &name;
  bool rc = remove_tinfo_pointer(tif, pname, til);
  return Py_BuildValue("(Os)", PyBool_FromLong(rc), pname != NULL ? *pname : NULL);
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
    return Py_BuildValue("(ssssi)", type, fields, cmt, fieldcmts, sclass);
  else
    Py_RETURN_NONE;
}

//</inline(py_typeinf)>

//<code(py_typeinf)>
//-------------------------------------------------------------------------
inline const p_list * PyW_Fields(PyObject *tp)
{
  return tp == Py_None ? NULL : (const p_list *) IDAPyBytes_AsString(tp);
}

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
      o = IDAPyStr_FromUTF8((const char *) (Thing).begin());  \
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
