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
%ignore foreach_strmem;
%ignore is_type_scalar;
%ignore get_type_signness;
%ignore is_type_signed;
%ignore is_type_unsigned;
%ignore get_struct_member;
%ignore idb_type_to_til;
%ignore get_idb_type;
%ignore apply_type_to_stkarg;
%ignore use_regarg_type_cb;
%ignore set_op_type_t;
%ignore is_stkarg_load_t;
%ignore has_delay_slot_t;
%ignore gen_use_arg_types;

// Kernel-only symbols
%ignore init_til;
%ignore save_til;
%ignore term_til;
%ignore determine_til;
%ignore get_tilpath;
%ignore autoload_til;
%ignore get_idainfo_by_type;
%ignore apply_callee_type;
%ignore propagate_stkargs;
%ignore build_anon_type_name;
%ignore type_names;
%ignore get_compiler_id;

%include "typeinf.hpp"

// Custom wrappers

%rename (load_til) load_til_wrap;
%inline %{
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

%rename (load_til_header_wrap) load_til_header_wrap;
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


