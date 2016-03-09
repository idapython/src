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
%ignore argloc_t::dstr;

%ignore extract_pstr;
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
// We want to handle 'get_named_type()' in a special way,
// but not tinfo_t::get_named_type().
//  http://stackoverflow.com/questions/27417884/how-do-i-un-ignore-a-specific-method-on-a-templated-class-in-swig
%ignore get_named_type;
%rename (get_named_type) py_get_named_type;
%ignore get_named_type64;
%rename (get_named_type64) py_get_named_type64;
%rename ("%s") tinfo_t::get_named_type;

%ignore udt_type_data_t::is_last_baseclass;

%rename (print_decls) py_print_decls;
%ignore print_decls;

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
%ignore get_arg_align;
%ignore align_stkarg_up;
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

%ignore callregs_t::findreg;

%ignore format_data_info_t;
%ignore valinfo_t;
%ignore print_c_data;
%ignore print_cdata;
%ignore format_c_data;
%ignore format_cdata;
%ignore format_cdata2;
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
%ignore enum_type_data_t::serialize_enum;
%ignore enum_type_data_t::deserialize_enum;
%ignore valstr_deprecated_t;
%ignore valinfo_deprecated_t;
%ignore valstr_deprecated2_t;
%ignore valinfo_deprecated2_t;

%ignore custloc_desc_t;
%ignore install_custom_argloc;
%ignore remove_custom_argloc;
%ignore retrieve_custom_argloc;

%{
//<code(py_typeinf)>
//</code(py_typeinf)>
%}

%extend til_t {

  til_t *base(int n)
  {
    return (n < 0 || n >= $self->nbases) ? NULL : $self->base[n];
  }
}

%extend tinfo_t {

  bool deserialize(
          const til_t *til,
          const type_t *type,
          const p_list *fields,
          const p_list *cmts = NULL)
  {
    return $self->deserialize(til, &type, &fields, cmts == NULL ? NULL : &cmts);
  }

  bool deserialize(
          const til_t *til,
          const char *_type,
          const char *_fields,
          const char *_cmts = NULL)
  {
    const type_t *type = (const type_t *) _type;
    const p_list *fields = (const p_list *) _fields;
    const p_list *cmts = (const p_list *) _cmts;
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
%simple_tinfo_t_container_lifecycle(ptr_type_data_t, (tinfo_t c=tinfo_t(), uchar bps=0), (c, bps));
%simple_tinfo_t_container_lifecycle(array_type_data_t, (size_t b=0, size_t n=0), (b, n));
%simple_tinfo_t_container_lifecycle(func_type_data_t, (), ());
%simple_tinfo_t_container_lifecycle(udt_type_data_t, (), ());

%template(funcargvec_t)   qvector<funcarg_t>;
%template(udtmembervec_t) qvector<udt_member_t>;

%include "typeinf.hpp"

// Custom wrappers

%rename (load_til) load_til_wrap;
%rename (load_til_header) load_til_header_wrap;
%rename (get_type_size0) py_get_type_size0;
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
