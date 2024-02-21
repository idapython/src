%{
#include <typeinf.hpp>
#include <struct.hpp>
%}

%constant bmask64_t DEFMASK64 = bmask64_t(-1);

// Most of these could be wrapped if needed
%ignore get_cc;
%ignore get_effective_cc;
%ignore ::use_golang_abi;
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
%ignore argloc_t::consume_scattered(scattered_aloc_t *p);
%ignore argpart_t::copy_from;

%ignore get_numbered_type(const til_t *, uint32, const type_t **, const p_list **, const char **, const p_list **, sclass_t *);
%rename (get_numbered_type) py_get_numbered_type;

%ignore NTF_NOSYNC;

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
%ignore fix_type_align;
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
%ignore name_requires_qualifier;
%ignore tinfo_visitor_t::level;
%ignore tinfo_t::serialize(qtype *, qtype *, qtype *, int) const;
%ignore tinfo_t::deserialize(const til_t *, const qtype *, const qtype *, const qtype *, const char *);
%ignore tinfo_get_innermost_udm;
%ignore save_tinfo2;
// Let's declare our own version of `deserialize_tinfo2` before
// SWiG hits the one that's in `typeinf.hpp` (and cannot, alas,
// enjoy the addition of the default value.)
%rename (deserialize_tinfo) deserialize_tinfo2;
%inline %{
idaman bool ida_export deserialize_tinfo2(tinfo_t *tif, const til_t *til, const type_t **ptype, const p_list **pfields, const p_list **pfldcmts, const char *cmt=nullptr);
%}
%ignore deserialize_tinfo;
%ignore deserialize_tinfo2;
%ignore get_udm_by_tid(tinfo_t *tif, udm_t *udm, tid_t tid);
%ignore get_edm_by_tid(tinfo_t *tif, edm_t *edm, tid_t tid);
%ignore get_type_by_tid(tinfo_t *tif, tid_t tid);
%ignore get_tinfo_by_edm_name(tinfo_t *tif, til_t *til, const char *mname);
%ignore value_repr_t__parse_value_repr;
%ignore enum_type_data_t__set_value_repr;

%ignore custloc_desc_t;
%ignore install_custom_argloc;
%ignore remove_custom_argloc;
%ignore retrieve_custom_argloc;
%ignore enum_type_visitor_t;
%ignore visit_edms;

%make_argout_errbuf_raise_when_null_result();

%{
//<code(py_typeinf)>
//</code(py_typeinf)>
%}

%extend argloc_t {
  void consume_scattered(const scattered_aloc_t &p)
  {
    $self->consume_scattered(new scattered_aloc_t(p));
  }
}

%extend til_t {

  til_t *base(int n)
  {
    return (n < 0 || n >= $self->nbases) ? nullptr : $self->base[n];
  }
}

//-------------------------------------------------------------------------
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
          const p_list *cmts = nullptr)
  {
    return $self->deserialize(til, &type, &fields, cmts == nullptr ? nullptr : &cmts);
  }

  tinfo_t copy() const
  {
    return *$self;
  }

  qstring __str__() const
  {
    qstring qs;
    $self->print(&qs);
    return qs;
  }
}

%apply size_t *OUTPUT {size_t *out_index};
%apply uint64 *OUTPUT {uint64 *out_bitoffset};

//---------------------------------------------------------------------
%define %tinfo_t_or_simple_tinfo_t_container_lifecycle(Type)
// Instead of re-defining all constructors, add the registering
// to a specialized 'ret' typemap
%typemap(ret) Type* Type::Type
{
  // %typemap(ret) Type* Type::Type
  til_register_python_##Type##_instance($1);
}
%extend Type {
  ~Type(void)
  {
    til_deregister_python_##Type##_instance($self);
    delete $self;
  }
}
%enddef

%tinfo_t_or_simple_tinfo_t_container_lifecycle(ptr_type_data_t);
%tinfo_t_or_simple_tinfo_t_container_lifecycle(array_type_data_t);
%tinfo_t_or_simple_tinfo_t_container_lifecycle(func_type_data_t);
%tinfo_t_or_simple_tinfo_t_container_lifecycle(udt_type_data_t);

// We can't use tinfo_t_or_simple_tinfo_t_container_lifecycle() for tinfo_t,
// as it would call til_register_python_tinfo_t_instance() a second time
// after '%typemap(out) tinfo_t *' already did it.
%extend tinfo_t {
  ~tinfo_t()
  {
    til_deregister_python_tinfo_t_instance($self);
    delete $self;
  }
}

%ignore tinfo_t::~tinfo_t();

%template(funcargvec_t)      qvector<funcarg_t>;
%template(reginfovec_t)      qvector<reg_info_t>;
%template(edmvec_t)          qvector<edm_t>;
%template(argpartvec_t)      qvector<argpart_t>;
%uncomparable_elements_qvector(valstr_t, valstrvec_t);
%uncomparable_elements_qvector(regobj_t, regobjvec_t);
%uncomparable_elements_qvector(type_attr_t, type_attrs_t);

%extend value_repr_t
{
  inline qstring __str__() const { qstring tmp; $self->print(&tmp); return tmp; }
}
%template(udtmembervec_template_t) qvector<udm_t>;
%ignore udt_type_data_t::VERSION;
%ignore udt_type_data_old_t;

%extend tinfo_t {
  PyObject *get_attr(const qstring &key, bool all_attrs=true)
  {
    bytevec_t bv;
    if ( $self->get_attr(key, &bv, all_attrs) )
      return PyUnicode_FromStringAndSize((const char *) bv.begin(), bv.size());
    else
      Py_RETURN_NONE;
  }
}
%ignore tinfo_t::get_attr;

%feature("director") predicate_t;

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
    $1 = new sclass_t(SC_UNK);
  else if ( PyLong_Check($input) )
    $1 = new sclass_t(sclass_t(PyLong_AsLong($input)));
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
//</inline(py_typeinf)>
%}

%cstring_output_maxsize(char *buf, size_t maxsize);

%pythoncode %{
#<pycode(py_typeinf)>
#</pycode(py_typeinf)>
%}
