#ifndef __PY_TYPEINF__
#define __PY_TYPEINF__

//<inline(py_typeinf)>
//-------------------------------------------------------------------------
PyObject *idc_parse_decl(til_t *til, const char *decl, int flags)
{
  tinfo_t tif;
  qstring name;
  qtype fields, type;
  bool ok = parse_decl(&tif, &name, til, decl, flags);
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
PyObject *py_calc_type_size(const til_t *til, PyObject *type)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  if ( PyBytes_Check(type) )
  {
    // To avoid release of 'data' during Py_BEGIN|END_ALLOW_THREADS section.
    borref_t typeref(type);
    const type_t *data = (type_t *)PyBytes_AsString(type);
    size_t sz;
    SWIG_PYTHON_THREAD_BEGIN_ALLOW;
    tinfo_t tif;
    tif.deserialize(til, &data, nullptr, nullptr);
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
static bool py_apply_type(
        til_t *til,
        const type_t *type,
        const p_list *fields,
        ea_t ea,
        int flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  bool rc;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t udttif;
  udm_t udm;
  ssize_t idx = udttif.get_udm_by_tid(&udm, ea);
  if ( type == nullptr || type[0] == '\0' )
  {
    if ( idx == -1 )
    {
      rc = has_ti(ea);
      if ( rc )
        del_tinfo(ea);
    }
  }
  else
  {
    tinfo_t tif;
    rc = tif.deserialize(til, &type, &fields, nullptr);
    if ( rc )
    {
      if ( idx != -1 )
        rc = udttif.set_udm_type(idx, tif) >= TERR_OK;
      else
        rc = apply_tinfo(ea, tif, flags);
    }
  }
  SWIG_PYTHON_THREAD_END_ALLOW;
  return rc;
}

//-------------------------------------------------------------------------
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
PyObject *py_unpack_object_from_idb(
        til_t *til,
        const type_t *type,
        const p_list *fields,
        ea_t ea,
        int pio_flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  idc_value_t idc_obj;
  error_t err;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t tif;
  tif.deserialize(til, &type, &fields);
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
PyObject *py_unpack_object_from_bv(
        til_t *til,
        const type_t *type,
        const p_list *fields,
        const bytevec_t &bytes,
        int pio_flags)
{
  idc_value_t idc_obj;
  error_t err;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t tif;
  tif.deserialize(til, &type, &fields);
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
PyObject *py_pack_object_to_idb(
        PyObject *obj,
        til_t *til,
        const type_t *type,
        const p_list *fields,
        ea_t ea,
        int pio_flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  borref_t obj_ref(obj);
  if ( !pyvar_to_idcvar_or_error(obj_ref, &idc_obj) )
    return nullptr;

  // Pack
  // error_t err;
  error_t err;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t tif;
  tif.deserialize(til, &type, &fields);
  err = pack_idcobj_to_idb(&idc_obj, tif, ea, pio_flags);
  SWIG_PYTHON_THREAD_END_ALLOW;
  return PyInt_FromLong(err);
}

//-------------------------------------------------------------------------
// Returns a tuple(Boolean, PackedBuffer or Error Code)
PyObject *py_pack_object_to_bv(
        PyObject *obj,
        til_t *til,
        const type_t *type,
        const p_list *fields,
        ea_t base_ea,
        int pio_flags)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();

  // Convert Python object to IDC object
  idc_value_t idc_obj;
  borref_t obj_ref(obj);
  if ( !pyvar_to_idcvar_or_error(obj_ref, &idc_obj) )
    return nullptr;

  // Pack
  relobj_t bytes;
  error_t err;
  SWIG_PYTHON_THREAD_BEGIN_ALLOW;
  tinfo_t tif;
  tif.deserialize(til, &type, &fields);
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
  if ( (flags & PT_SEMICOLON) != 0 )
  {
    hti |= HTI_SEMICOLON;
    flags &= ~PT_SEMICOLON;
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
PyObject *py_print_decls(text_sink_t &printer, til_t *til, PyObject *ordinals, uint32 flags)
{
  if ( !PyList_Check(ordinals) )
  {
    PyErr_SetString(PyExc_ValueError, "'ordinals' must be a list");
    return nullptr;
  }

  Py_ssize_t nords = PyList_Size(ordinals);
  ordvec_t _ordinals;
  _ordinals.reserve(size_t(nords));
  for ( Py_ssize_t i = 0; i < nords; ++i )
  {
    borref_t item(PyList_GetItem(ordinals, i));
    if ( !item || !PyLong_Check(item.o) )
    {
      qstring msg;
      msg.sprnt("ordinals[%d] is not a valid value", int(i));
      PyErr_SetString(PyExc_ValueError, msg.begin());
      return nullptr;
    }
    uint32 ord = PyLong_AsLong(item.o);
    _ordinals.push_back(ord);
  }
  return PyLong_FromLong(print_decls(printer, til, _ordinals.empty() ? nullptr : &_ordinals, flags));
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

//-------------------------------------------------------------------------
static tinfo_code_t py_set_numbered_type(
        til_t *ti,
        uint32 ordinal,
        int ntf_flags,
        const char *name,
        const type_t *type,
        const p_list *fields=nullptr,
        const char *cmt=nullptr,
        const p_list *fldcmts=nullptr,
        const sclass_t *sclass=nullptr)
{
  tinfo_t tif;
  return tif.deserialize(ti, &type, &fields, &fldcmts, cmt)
       ? tif.set_numbered_type(ti, ordinal, ntf_flags, name)
       : TERR_BAD_TYPE;
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
