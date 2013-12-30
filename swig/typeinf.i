// Most of these could be wrapped if needed
%ignore get_cc;
%ignore get_cc_type_size;
%ignore set_argloc;
%ignore set_dt;
%ignore set_da;
%ignore set_de;
%ignore get_dt;
%ignore get_da;
%ignore get_de;
%ignore skip_ptr_type_header;
%ignore skip_array_type_header;
%ignore unpack_object_from_idb;
%ignore unpack_object_from_bv;
%ignore pack_object_to_idb;
%ignore pack_object_to_bv;
%ignore typend;
%ignore typlen;
%ignore typncpy;
%ignore tppncpy;
%ignore typcmp;
%ignore typdup;
%ignore equal_types;
%ignore resolve_typedef;
%ignore is_resolved_type_const;
%ignore is_resolved_type_void;
%ignore is_resolved_type_ptr;
%ignore is_resolved_type_func;
%ignore is_resolved_type_array;
%ignore is_resolved_type_complex;
%ignore is_resolved_type_struct;
%ignore is_resolved_type_union;
%ignore is_resolved_type_enum;
%ignore is_resolved_type_bitfld;
%ignore is_castable;
%ignore remove_constness;
%ignore remove_pointerness;
%ignore get_int_type_bit;
%ignore get_unk_type_bit;
%ignore tns;

%ignore til_t::base;
%ignore til_t::syms;
%ignore til_t::types;
%ignore til_t::macros;

%ignore add_base_tils;
%ignore sort_til;
%ignore til_add_macro;
%ignore til_next_macro;

%ignore parse_subtype;
%ignore calc_type_size;
%ignore get_type_size;
%ignore get_type_size0;
%ignore skip_type;
%ignore get_pointer_object_size;

%ignore descr_t;

%ignore unpack_type;
%ignore print_type_to_one_line;
%ignore print_type_to_many_lines;
%ignore print_type;
%ignore show_type;
%ignore show_plist;
%ignore show_bytes;
%ignore skip_function_arg_names;
%ignore perform_funcarg_conversion;
%ignore get_argloc_info;

%ignore extract_pstr;
%ignore extract_name;
%ignore skipName;
%ignore extract_comment;
%ignore skipComment;
%ignore extract_fargcmt;
%ignore skip_argloc;
%ignore extract_argloc;

%ignore h2ti;
%ignore h2ti_warning;
%ignore parse_type;
%ignore parse_types;
%ignore get_named_type;

%ignore set_named_type;
%ignore get_named_type_size;

%ignore decorate_name;
%ignore decorate_name3;
%ignore gen_decorate_name;
%ignore calc_bare_name;
%ignore calc_bare_name3;
%ignore calc_cpp_name;
%ignore calc_c_cpp_name;
%ignore calc_c_cpp_name3;
%ignore predicate_t;
%ignore local_predicate_t;
%ignore tinfo_predicate_t;
%ignore local_tinfo_predicate_t;
%ignore choose_named_type;
%ignore get_default_align;
%ignore align_size;
%ignore align_size;
%ignore get_default_enum_size;
%ignore max_ptr_size;
%ignore based_ptr_name_and_size;
%ignore calc_arglocs;

%ignore apply_type;
%ignore apply_callee_type;
%ignore guess_func_type;
%ignore guess_type;

%ignore build_funcarg_arrays;
%ignore free_funcarg_arrays;
%ignore extract_func_ret_type;
%ignore calc_names_cmts;
%ignore resolve_complex_type;
%ignore visit_strmems;
%ignore foreach_strmem;
%ignore is_type_scalar;
%ignore get_type_signness;
%ignore is_type_signed;
%ignore is_type_unsigned;
%ignore get_struct_member;
%ignore idb_type_to_til;
%ignore get_idb_type;

%ignore apply_type_to_stkarg;
%rename (apply_type_to_stkarg) py_apply_type_to_stkarg;
%ignore print_type;
%rename (print_type) py_print_type;
%rename (calc_type_size) py_calc_type_size;
%rename (apply_type) py_apply_type;

%ignore use_regarg_type_cb;
%ignore set_op_type_t;
%ignore is_stkarg_load_t;
%ignore has_delay_slot_t;
%ignore gen_use_arg_types;
%ignore enable_numbered_types;
%ignore compact_numbered_types;

%ignore type_pair_vec_t::add_names;

%ignore format_data_info_t;
%ignore valinfo_t;
%ignore print_c_data;
%ignore format_c_data;
%ignore format_c_number;
%ignore get_enum_member_expr;
%ignore extend_sign;

// Kernel-only symbols
%ignore build_anon_type_name;
%ignore enum_type_data_t::is_signed;
%ignore enum_type_data_t::is_unsigned;
%ignore enum_type_data_t::get_sign;
%ignore bitfield_type_data_t::serialize;
%ignore func_type_data_t::serialize;
%ignore func_type_data_t::deserialize;
%ignore enum_type_data_t::get_enum_base_type;
%ignore enum_type_data_t::deserialize_enum;
%ignore valstr_deprecated_t;
%ignore valinfo_deprecated_t;

%include "typeinf.hpp"

// Custom wrappers

%rename (load_til) load_til_wrap;
%rename (get_type_size0) py_get_type_size0;
%rename (idc_get_type_raw) py_idc_get_type_raw;
%rename (idc_get_local_type_raw) py_idc_get_local_type_raw;
%rename (unpack_object_from_idb) py_unpack_object_from_idb;
%rename (unpack_object_from_bv) py_unpack_object_from_bv;
%rename (pack_object_to_idb) py_pack_object_to_idb;
%rename (pack_object_to_bv) py_pack_object_to_bv;
%inline %{
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
til_t *load_til(const char *tildir, const char *name)
{
  char errbuf[MAXSTR];
  til_t *res = load_til(tildir, name, errbuf, sizeof(errbuf));
  if ( res == NULL )
    PyErr_SetString(PyExc_RuntimeError, errbuf);
  return res;
}
%}

%rename (load_til_header) load_til_header_wrap;
%inline %{
til_t *load_til_header_wrap(const char *tildir, const char *name)
{
  char errbuf[MAXSTR];
  til_t *res = load_til_header(tildir, name, errbuf, sizeof(errbuf));;
  if ( res == NULL )
    PyErr_SetString(PyExc_RuntimeError, errbuf);
  return res;
}
%}

%cstring_output_maxsize(char *buf, size_t maxsize);

%pythoncode %{
#<pycode(py_typeinf)>

def get_type_size0(ti, tp):
    """
    DEPRECATED. Please use calc_type_size instead
    Returns the size of a type
    @param ti: Type info. 'idaapi.cvar.idati' can be passed.
    @param tp: type string
    @return:
        - None on failure
        - The size of the type
    """
    return calc_type_size(ti, tp)

#</pycode(py_typeinf)>

%}
