%module(docstring="IDA Plugin SDK API wrapper: typeinf",directors="1",threads="1") ida_typeinf
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_TYPEINF
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_TYPEINF
  #define HAS_DEP_ON_INTERFACE_TYPEINF
#endif
#ifndef HAS_DEP_ON_INTERFACE_IDP
  #define HAS_DEP_ON_INTERFACE_IDP
#endif
%include "header.i"
%{
#include <typeinf.hpp>
#include <struct.hpp>
%}

%import "idp.i"

// Most of these could be wrapped if needed
%ignore get_cc;
%ignore get_cc_type_size;
%ignore get_de;
%ignore skip_ptr_type_header;
%ignore skip_array_type_header;
%ignore pack_object_to_idb;
%ignore typend;
%ignore typlen;
%ignore typncpy;
%ignore tppncpy;
%ignore typcmp;
%ignore typdup;
%ignore get_int_type_bit;
%ignore get_unk_type_bit;
%ignore tns;

%ignore til_t::syms;
%ignore til_t::types;
%ignore til_t::macros;

%ignore add_base_tils;
%ignore sort_til;
%ignore til_add_macro;
%ignore til_next_macro;

%ignore parse_subtype;

%ignore descr_t;

%ignore show_type;
%ignore show_plist;
%ignore show_bytes;
%ignore skip_function_arg_names;
%ignore perform_funcarg_conversion;
%ignore get_argloc_info;
%ignore argloc_t::dstr;
%ignore argpart_t::copy_from;

%ignore get_numbered_type(const til_t *, uint32, const type_t **, const p_list **, const char **, const p_list **, sclass_t *);
%rename (get_numbered_type) py_get_numbered_type;

%ignore skipName;
%ignore extract_comment;
%ignore skipComment;
%ignore extract_fargcmt;
%ignore skip_argloc;

%ignore h2ti;
%ignore h2ti_warning;
// We want to handle 'get_named_type()' in a special way,
// but not tinfo_t::get_named_type().
//  http://stackoverflow.com/questions/27417884/how-do-i-un-ignore-a-specific-method-on-a-templated-class-in-swig
%ignore get_named_type;
%rename (get_named_type) py_get_named_type;
%ignore get_named_type64;
%rename (get_named_type64) py_get_named_type64;
%rename ("%s") tinfo_t::get_named_type;

%rename (print_decls) py_print_decls;
%ignore print_decls;

// let's get rid of this one, without prohibiting tinfo_t::set_named_type()
%ignore set_named_type(
        til_t *,
        const char *,
        int,
        const type_t *,
        const p_list *,
        const char *,
        const p_list *,
        const sclass_t *,
        const uint32 *);
%ignore get_named_type_size;

%ignore decorate_name;
%ignore calc_bare_name3;
%ignore tinfo_predicate_t;
%ignore local_tinfo_predicate_t;
%ignore get_default_align;
%ignore align_size;
%ignore align_size;
%ignore get_arg_align;
%ignore align_stkarg_up;
%ignore get_default_enum_size;
%ignore max_ptr_size;
%ignore based_ptr_name_and_size;

%ignore apply_callee_type;
%ignore get_arg_addrs;
%rename (get_arg_addrs) py_get_arg_addrs;

%ignore calc_names_cmts;
%ignore idb_type_to_til;
%ignore get_idb_type;

%ignore calc_type_size;
%rename (calc_type_size) py_calc_type_size;
%ignore apply_type;
%rename (apply_type) py_apply_type;

%ignore use_regarg_type_cb;
%ignore is_stkarg_load_t;
%ignore has_delay_slot_t;
%ignore gen_use_arg_types;
%ignore enable_numbered_types;
%ignore compact_numbered_types;

%ignore callregs_t::findreg;

%ignore format_data_info_t;
%ignore valinfo_t;
%ignore print_cdata;
%ignore format_cdata;
%ignore format_c_number;
%ignore extend_sign;

// Kernel-only symbols
%ignore build_anon_type_name;
%ignore bitfield_type_data_t::serialize;
%ignore func_type_data_t::serialize;
%ignore func_type_data_t::deserialize;
%ignore tinfo_t::serialize(qtype *, qtype *, qtype *, int) const;
%ignore name_requires_qualifier;
%ignore tinfo_visitor_t::level;

%ignore custloc_desc_t;
%ignore install_custom_argloc;
%ignore remove_custom_argloc;
%ignore retrieve_custom_argloc;

%{
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
%}

%extend til_t {

  til_t *base(int n)
  {
    return (n < 0 || n >= $self->nbases) ? NULL : $self->base[n];
  }
}

%extend tinfo_t {

  PyObject *serialize(
          int sudt_flags=SUDT_FAST|SUDT_TRUNC) const
  {
    return py_tinfo_t_serialize($self, sudt_flags);
  }

  bool deserialize(
          const til_t *til,
          const type_t *type,
          const p_list *fields,
          const p_list *cmts = NULL)
  {
    return $self->deserialize(til, &type, &fields, cmts == NULL ? NULL : &cmts);
  }

  // The typemap in typeconv.i will take care of registering newly-constructed
  // tinfo_t instances. However, there's no such thing as a destructor typemap.
  // Therefore, we need to do the grunt work of de-registering ourselves.
  // Note: The 'void' here is important: Without it, SWIG considers it to
  //       be a different destructor (which, of course, makes a ton of sense.)
  ~tinfo_t(void)
  {
    til_deregister_python_tinfo_t_instance($self);
    delete $self;
  }

  qstring __str__() const {
    qstring qs;
    $self->print(&qs);
    return qs;
  }
}
%ignore tinfo_t::~tinfo_t(void);

//---------------------------------------------------------------------
// NOTE: This will ***NOT*** work for tinfo_t objects. Those must
// be created and owned (or not) according to the kind of access.
// To implement that, we use typemaps (see typeconv.i).
%define %simple_tinfo_t_container_lifecycle(Type, CtorSig, ParamsList)
%extend Type {
  Type CtorSig
  {
    Type *inst = new Type ParamsList;
    til_register_python_##Type##_instance(inst);
    return inst;
  }

  ~Type(void)
  {
    til_deregister_python_##Type##_instance($self);
    delete $self;
  }
}
%enddef
%simple_tinfo_t_container_lifecycle(ptr_type_data_t, (tinfo_t c=tinfo_t(), uchar bps=0, tinfo_t p=tinfo_t(), int32 d=0), (c, bps, p, d));
%simple_tinfo_t_container_lifecycle(array_type_data_t, (size_t b=0, size_t n=0), (b, n));
%simple_tinfo_t_container_lifecycle(func_type_data_t, (), ());
%simple_tinfo_t_container_lifecycle(udt_type_data_t, (), ());

%template(funcargvec_t)   qvector<funcarg_t>;
%template(udtmembervec_t) qvector<udt_member_t>;
%template(reginfovec_t)   qvector<reg_info_t>;
%uncomparable_elements_qvector(type_attr_t, type_attrs_t);

%extend tinfo_t {
  PyObject *get_attr(const qstring &key, bool all_attrs=true)
  {
    bytevec_t bv;
    if ( $self->get_attr(key, &bv, all_attrs) )
      return IDAPyStr_FromUTF8AndSize(
              (const char *) bv.begin(),
              bv.size());
    else
      Py_RETURN_NONE;
  }
}
%ignore tinfo_t::get_attr;

%feature("director") predicate_t;

%ignore load_til;
%rename (load_til) py_load_til;
%ignore load_til_header;
%rename (load_til_header) py_load_til_header;

%ignore remove_tinfo_pointer;
%rename (remove_tinfo_pointer) py_remove_tinfo_pointer;

%cstring_output_buf_and_size_returning_charptr(
        2,
        ea_t ea,
        char *buf,
        size_t bufsize); // idc_guess_type, idc_get_type

// set_numbered_type()
%typemap(in) const sclass_t * {
  // %typemap(in) const sclass_t *
  if ( $input == Py_None )
    $1 = new sclass_t(sc_unk);
  else if ( IDAPyInt_Check($input) )
    $1 = new sclass_t(sclass_t(IDAPyInt_AsLong($input)));
  else
    SWIG_exception_fail(
            SWIG_ValueError,
            "invalid argument " "in method '" "$symname" "', argument " "$argnum"" of type '" "$1_type""'");
}
%typemap(freearg) const sclass_t * {
  // %typemap(freearg) const sclass_t *
  delete $1;
}

%include "typeinf.hpp"

// Custom wrappers

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
%}

%cstring_output_maxsize(char *buf, size_t maxsize);

%pythoncode %{
#<pycode(py_typeinf)>

import ida_idaapi
ida_idaapi._listify_types(
    reginfovec_t)

#</pycode(py_typeinf)>
%}
%pythoncode %{
if _BC695:
    BFI_NOCONST=0
    BFI_NOLOCS=0
    NTF_NOIDB=0
    PRVLOC_STKOFF=PRALOC_VERIFY
    PRVLOC_VERIFY=PRALOC_STKOFF
    TERR_TOOLONGNAME=TERR_WRONGNAME
    @bc695redef
    def add_til(name, flags=0):
        return _ida_typeinf.add_til(name, flags)
    add_til2=add_til
    def apply_decl(arg0, arg1, arg2=None, arg3=0):
        if type(arg0) in [int, long]: # old apply_cdecl()
            return _ida_typeinf.apply_cdecl(cvar.idati, arg0, arg1, 0)
        else:
            assert(arg2 is not None)
            return _ida_typeinf.apply_cdecl(arg0, arg1, arg2, arg3)
    apply_cdecl2=apply_decl
    apply_tinfo2=apply_tinfo
    calc_c_cpp_name4=calc_c_cpp_name
    import ida_idaapi
    callregs_init_regs=ida_idaapi._BC695.dummy
    choose_local_type=choose_local_tinfo
    def choose_named_type2(root_til, title, ntf_flags, func, out_sym):
        class func_pred_t(predicate_t):
            def __init__(self, func):
                predicate_t.__init__(self)
                self.func = func
            def should_display(self, til, name, tp, flds):
                return self.func(name, tp, flds)
        fp = func_pred_t(func)
        return choose_named_type(out_sym, root_til, title, ntf_flags, fp)
    deref_ptr2=deref_ptr
    extract_varloc=extract_argloc
    const_vloc_visitor_t=const_aloc_visitor_t
    for_all_const_varlocs=for_all_const_arglocs
    for_all_varlocs=for_all_arglocs
    def gen_decorate_name3(name, mangle, cc):
        return gen_decorate_name(name, mangle, cc, None) # ATM gen_decorate_name doesn't use its tinfo_t
    get_enum_member_expr2=get_enum_member_expr
    get_idainfo_by_type3=get_idainfo_by_type
    def guess_func_tinfo2(pfn, tif):
        return guess_tinfo(pfn.start_ea, tif)
    @bc695redef
    def load_til(name, tildir=None, *args):
        # 6.95 C++ prototypes
        # idaman til_t *ida_export load_til(const char *tildir, const char *name, char *errbuf, size_t bufsize);
        # idaman til_t *ida_export load_til2(                   const char *name, char *errbuf, size_t bufsize);
        #
        # 6.95 Python prototypes
        # load_til(tildir, name)
        # load_til(tildir, name, errbuf, bufsize)
        # load_til2(name, errbuf, bufsize=0)
        #
        # -> it's virtually impossible to tell whether it's load_til2(),
        # or load_til() that's called since they both take 2 first string
        # arguments. We'll rely the contents of those strings...
        if name is None or name == "": # load_til(), with an empty tildir
            name = tildir
            tildir = ""
            return _ida_typeinf.load_til(name, tildir)
        else:
            return _ida_typeinf.load_til(name, tildir)
    load_til2=load_til
    lower_type2=lower_type
    optimize_varloc=optimize_argloc
    def parse_decl2(til, decl, tif, flags):
        return _ida_typeinf.parse_decl(tif, til, decl, flags)
    @bc695redef
    def print_type(ea, flags):
        if isinstance(flags, bool):
            flags = PRTYPE_1LINE if flags else 0
        return _ida_typeinf.print_type(ea, flags)
    def print_type2(ea, flags):
        return _ida_typeinf.print_type(ea, flags)
    print_type3=_ida_typeinf.print_type
    print_varloc=print_argloc
    def resolve_typedef2(til, p, *args):
        return _ida_typeinf.resolve_typedef(til, p)
    scattered_vloc_t=scattered_aloc_t
    set_compiler2=set_compiler
    varloc_t=argloc_t
    varpart_t=argpart_t
    verify_varloc=verify_argloc
    vloc_visitor_t=aloc_visitor_t
    def guess_tinfo(*args):
        if isinstance(args[1], tinfo_t): # 6.95: id, tinfo_t
            tid, tif = args
        else:                            # 7.00: tinfo_t, id
            tif, tid = args
        return _ida_typeinf.guess_tinfo(tif, tid)
    guess_tinfo2=guess_tinfo
    def find_tinfo_udt_member(*args):
        if isinstance(args[2], udt_member_t): # 6.95: typid, strmem_flags, udm
              typid, strmem_flags, udm = args
        else:                                 # 7.00: udm, typid, strmem_flags
              udm, typid, strmem_flags = args
        return _ida_typeinf.find_tinfo_udt_member(udm, typid, strmem_flags)
    def __tinfo_t_find_udt_member(self, *args):
        if isinstance(args[1], udt_member_t): # 6.95: strmem_flags, udm
              strmem_flags, udm = args
        else:                                 # 7.00: udm, strmem_flags
              udm, strmem_flags = args
        return _ida_typeinf.tinfo_t_find_udt_member(self, udm, strmem_flags)
    tinfo_t.find_udt_member=__tinfo_t_find_udt_member
    def save_tinfo(*args):
        if isinstance(args[4], tinfo_t): # 6.95: til_t, size_t, name, int, tinfo_t
            til, _ord, name, ntf_flags, tif = args
        else:                            # 7.00: tinfo_t, til_t, size_t, name, int
            tif, til, _ord, name, ntf_flags = args
        return _ida_typeinf.save_tinfo(tif, til, _ord, name, ntf_flags)

%}