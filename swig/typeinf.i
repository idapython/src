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
%ignore use_regarg_type_cb;
%ignore set_op_type_t;
%ignore is_stkarg_load_t;
%ignore has_delay_slot_t;
%ignore gen_use_arg_types;
%ignore enable_numbered_types;

%ignore type_pair_vec_t::add_names;

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

%ignore build_func_type;

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

%cstring_output_maxsize(char *buf, size_t maxsize);

%inline %{
/* Parse types from a string or file. See ParseTypes() in idc.py */
int idc_parse_types(const char *input, int flags)
{
    int hti = ((flags >> 4) & 7) << HTI_PAK_SHIFT;

    if ((flags & 1) != 0)
        hti |= HTI_FIL;

    return parse_types2(input, (flags & 2) == 0 ? msg : NULL, hti);
}

char *idc_get_type(ea_t ea, char *buf, size_t bufsize)
{
    type_t type[MAXSTR];
    p_list fnames[MAXSTR];
 
    if (get_ti(ea, type, sizeof(type), fnames, sizeof(fnames)))
    {
        int code = print_type_to_one_line(buf, bufsize, idati, type,
                                          NULL, NULL, fnames);
        if (code == T_NORMAL)
            return buf;
    }                                                              \
    return NULL;
}

char *idc_guess_type(ea_t ea, char *buf, size_t bufsize)
{
    type_t type[MAXSTR];
    p_list fnames[MAXSTR];
 
    if (guess_type(ea, type, sizeof(type), fnames, sizeof(fnames)))
    {
        int code = print_type_to_one_line(buf, bufsize, idati, type,
                                          NULL, NULL, fnames);
        if (code == T_NORMAL)
            return buf;
    }                                                              \
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
