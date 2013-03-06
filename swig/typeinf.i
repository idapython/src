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
%ignore gen_decorate_name;
%ignore calc_bare_name;
%ignore calc_cpp_name;
%ignore calc_c_cpp_name;
%ignore predicate_t;
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
%ignore init_til;
%ignore save_til;
%ignore term_til;
%ignore determine_til;
%ignore sync_from_til;
%ignore get_tilpath;
%ignore autoload_til;
%ignore get_idainfo_by_type;
%ignore apply_callee_type;
%ignore propagate_stkargs;
%ignore build_anon_type_name;
%ignore type_names;
%ignore get_compiler_id;
%ignore reloc_info_t;
%ignore relobj_t;
%ignore regobj_t;
%ignore build_func_type;

%ignore append_type_name;
%ignore for_all_types_ex;
%ignore fix_idb_type;
%ignore pdb2ti;
%ignore process_sdacl_padding;

%include "typeinf.hpp"

// Custom wrappers

%rename (load_til) load_til_wrap;
%rename (get_type_size0) py_get_type_size0;
%rename (idc_get_type_raw) py_idc_get_type_raw;
%rename (unpack_object_from_idb) py_unpack_object_from_idb;
%rename (unpack_object_from_bv) py_unpack_object_from_bv;
%rename (pack_object_to_idb) py_pack_object_to_idb;
%rename (pack_object_to_bv) py_pack_object_to_bv;
%inline %{
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
til_t * load_til(const char *tildir, const char *name)
{
    char errbuf[4096];
    til_t *res;

    res = load_til(tildir, name, errbuf, sizeof(errbuf));

    if (!res)
    {
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }

    return res;
}
%}

%rename (load_til_header) load_til_header_wrap;
%inline %{
til_t * load_til_header_wrap(const char *tildir, const char *name)
{
    char errbuf[4096];
    til_t *res;

    res = load_til_header(tildir, name, errbuf, sizeof(errbuf));;

    if (!res)
    {
        PyErr_SetString(PyExc_RuntimeError, errbuf);
        return NULL;
    }

    return res;
}
%}

%cstring_output_maxsize(char *buf, size_t maxsize);

%inline %{
/* Parse types from a string or file. See ParseTypes() in idc.py */
int idc_parse_types(const char *input, int flags)
{
    int hti = ((flags >> 4) & 7) << HTI_PAK_SHIFT;

    if ((flags & 1) != 0)
        hti |= HTI_FIL;

    return parse_decls(idati, input, (flags & 2) == 0 ? msg : NULL, hti);
}

PyObject *py_idc_get_type_raw(ea_t ea)
{
    qtype type, fields;
    if (get_tinfo(ea, &type, &fields))
    {
      return Py_BuildValue("(ss)", (char *)type.c_str(), (char *)fields.c_str());
    }
    else
    {
      Py_RETURN_NONE;
    }
}

char *idc_get_type(ea_t ea, char *buf, size_t bufsize)
{
    qtype type, fnames;

    if (get_tinfo(ea, &type, &fnames))
    {
        int code = print_type_to_one_line(buf, bufsize, idati, type.c_str(),
                                          NULL, NULL, fnames.c_str());
        if (code == T_NORMAL)
            return buf;
    }
    return NULL;
}

char *idc_guess_type(ea_t ea, char *buf, size_t bufsize)
{
    qtype type, fnames;

    if (guess_tinfo(ea, &type, &fnames))
    {
        int code = print_type_to_one_line(buf, bufsize, idati, type.c_str(),
                                          NULL, NULL, fnames.c_str());
        if (code == T_NORMAL)
            return buf;
    }
    return NULL;
}

int idc_set_local_type(int ordinal, const char *dcl, int flags)
{
    if (dcl == NULL || dcl[0] == '\0')
    {
        if (!del_numbered_type(idati, ordinal))
            return 0;
    }
    else
    {
        qstring name;
        qtype type;
        qtype fields;

        if (!parse_decl(idati, dcl, &name, &type, &fields, flags))
            return 0;

        if (ordinal <= 0)
	{
            if (!name.empty())
                ordinal = get_type_ordinal(idati, name.c_str());

            if (ordinal <= 0)
                ordinal = alloc_type_ordinal(idati);
	}

        if (!set_numbered_type(idati, ordinal, 0, name.c_str(), type.c_str(), fields.c_str()))
            return 0;
    }
    return ordinal;
}

int idc_get_local_type(int ordinal, int flags, char *buf, size_t maxsize)
{
    const type_t *type;
    const p_list *fields;

    if (!get_numbered_type(idati, ordinal, &type, &fields))
    {
        buf[0] = 0;
        return false;
    }

    qstring res;
    const char *name = get_numbered_type_name(idati, ordinal);

    if (print_type_to_qstring(&res, NULL, 2, 40, flags, idati, type, name, NULL, fields) <= 0)
    {
        buf[0] = 0;
        return false;
    }

    qstrncpy(buf, res.c_str(), maxsize);
    return true;
}

char idc_get_local_type_name(int ordinal, char *buf, size_t bufsize)
{
    const char *name = get_numbered_type_name(idati, ordinal);

    if (name == NULL)
        return false;

    qstrncpy(buf, name, bufsize);
    return true;
}
%}
