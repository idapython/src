
import argparse
p = argparse.ArgumentParser()
p.add_argument("--api-695", required=True, help="Path to the 6.95 API desc file")
p.add_argument("--api-700", required=True, help="Path to the 7.00 API desc file")

args = p.parse_args()
with open(args.api_695, "r") as fin:
    api_695 = eval(fin.read())
with open(args.api_700, "r") as fin:
    api_700 = eval(fin.read())

renamed_modules = {
    "ida_area" : "ida_range",
    "ida_queue" : "ida_problems",
    "ida_srarea" : "ida_segregs",
    "ida_queue" : "ida_problems",
    "ida_ints" : "ida_bytes",
}

renamed_symbols = {
    "ida_area" : {
        "AREACB_TYPE_FUNC" : "RANGE_KIND_FUNC",
        "AREACB_TYPE_FUNC" : "RANGE_KIND_FUNC",
        "AREACB_TYPE_HIDDEN_AREA" : "RANGE_KIND_HIDDEN_RANGE",
        "AREACB_TYPE_SEGMENT" : "RANGE_KIND_SEGMENT",
        "AREACB_TYPE_UNKNOWN" : "RANGE_KIND_UNKNOWN",
        "area_t_print(*args)" : "range_t_print(*args)",
        "areavec_t" : "rangevec_t",
    },

    "ida_auto" : {
        "analyze_area" : "plan_and_wait",
        "autoCancel" : "auto_cancel",
        "autoIsOk" : "auto_is_ok",
        "autoMark" : "auto_mark",
        "autoUnmark" : "auto_unmark",
        "autoWait" : "auto_wait",
    },

    "ida_bytes" : {
        "doExtra(_)" : "doExtra(_, *args)",
        "noExtra(_)" : "noExtra(_, *args)",
        "do3byte(*args)" : "do3byte(_, *args)",
        "f_is3byte(*args)" : "f_is3byte(_, *args)",
        "get_3byte(*args)" : "get_3byte(_, *args)",
        "is3byte(*args)" : "is3byte(_, *args)",
        "invalidate_visea_cache(*args)" : "invalidate_visea_cache(_, *args)",
    },

    "ida_dbg" : {
        "get_tev_reg_mem_ea(*args)" : "get_tev_reg_mem_ea(_, _)",
        "get_tev_reg_mem_qty(*args)" : "get_tev_reg_mem_qty(_)",
        "get_tev_reg_val(*args)" : "get_tev_reg_val(_, _)",
    },

    "ida_frame" : {
        "ida_area" : "ida_range",

    },

    "ida_funcs" : {
        "ida_area" : "ida_range",

    },

    "ida_gdl" : {
        "ida_area" : "ida_range",

    },

    "ida_hexrays" : {
        "call_helper(*args)" : "call_helper(_, _, *rest)",
        "dereference(*args)" : "dereference(_, _, =False)",
        "lnot(*args)" : "lnot(_)",
        "make_ref(*args)" : "make_ref(_)",
        "new_block(*args)" : "new_block()",
    },

    "ida_ida" : {
        "ansi2idb(*args)" : "ansi2idb(_, _)",
        "idb2scr(*args)" : "idb2scr(_, _)",
        "scr2idb(*args)" : "scr2idb(_, _)",
    },

    "ida_kernwin" : {
        "TODO" : [
            "Choose",
            "EMPTY_SEL",
            "END_SEL",
            "START_SEL",
        ],
        "askident(*args)" : "askident(_, _)",
    },

    "ida_nalt" : {
        "switch_info_ex_t_assign" : "switch_info_t_assign",
        "switch_info_ex_t_create" : "switch_info_t_create",
        "switch_info_ex_t_destroy" : "switch_info_t_destroy",
        "switch_info_ex_t_get_custom" : "switch_info_t_get_custom",
        "switch_info_ex_t_get_defjump" : "switch_info_t_get_defjump",
        "switch_info_ex_t_get_elbase" : "switch_info_t_get_elbase",
        "switch_info_ex_t_get_flags" : "switch_info_t_get_flags",
        "switch_info_ex_t_get_ind_lowcase" : "switch_info_t_get_ind_lowcase",
        "switch_info_ex_t_get_jcases" : "switch_info_t_get_jcases",
        "switch_info_ex_t_get_jumps" : "switch_info_t_get_jumps",
        "switch_info_ex_t_get_ncases" : "switch_info_t_get_ncases",
        "switch_info_ex_t_get_regdtyp" : "switch_info_t_get_regdtyp",
        "switch_info_ex_t_get_regnum" : "switch_info_t_get_regnum",
        "switch_info_ex_t_get_startea" : "switch_info_t_get_startea",
        "switch_info_ex_t_get_values_lowcase" : "switch_info_t_get_values_lowcase",
        "switch_info_ex_t_set_custom" : "switch_info_t_set_custom",
        "switch_info_ex_t_set_defjump" : "switch_info_t_set_defjump",
        "switch_info_ex_t_set_elbase" : "switch_info_t_set_elbase",
        "switch_info_ex_t_set_flags" : "switch_info_t_set_flags",
        "switch_info_ex_t_set_ind_lowcase" : "switch_info_t_set_ind_lowcase",
        "switch_info_ex_t_set_jcases" : "switch_info_t_set_jcases",
        "switch_info_ex_t_set_jumps" : "switch_info_t_set_jumps",
        "switch_info_ex_t_set_ncases" : "switch_info_t_set_ncases",
        "switch_info_ex_t_set_regdtyp" : "switch_info_t_set_regdtyp",
        "switch_info_ex_t_set_regnum" : "switch_info_t_set_regnum",
        "switch_info_ex_t_set_startea" : "switch_info_t_set_startea",
        "switch_info_ex_t_set_values_lowcase" : "switch_info_t_set_values_lowcase",
    },

    "ida_segment" : {
        "ida_area" : "ida_range",
    },

    "ida_srarea" : {
        "ida_area" : "ida_range",
        "is_segreg_locked(*args)" : "is_segreg_locked(_, *args)",
    },

    "ida_typeinf" : {
        "callregs_init_regs(*args)" : "callregs_init_regs(_, *args)",
        "print_type3(*args)" : "print_type",
    },

    "idc" : {
        "Fatal(_)" : "Fatal(*args)",
        "Warning(_)" : "Warning(*args)",
    },
}

removed_symbols = {

    "ida_allins" : [
        "NN_vmovntsd",
        "NN_vmovntss",
    ],

    "ida_area" : [
        "AREACB_TYPE_SRAREA",
        "area_visitor2_t",
        "areacb_t",
        "lock_area",
    ],

    "ida_auto" : [
        "autoGetName",
        "autoStep",
    ],

    "ida_bytes" : [
        "cvar",
        # the following have been removed
            "doVar",
        "f_isUnknown",
        "getRadixEA",
        "get_data_type_size",
        "get_typeinfo",
        "ida_area",
        "isVar",
        "lowbits",
        "noImmd",
        "power2",
        "setFlags",
        "set_typeinfo",
    ],

    "ida_dbg" : [
        "SRCIT_REGVAR",
        "SRCIT_RRLVAR",
        "SRCIT_STKVAR",
    ],

    "ida_diskio" : [
        "call_system",
        "echsize",
        "echsize64",
        "ecreate",
        "ecreateT",
        "enumerate_system_files",
        "eseek",
        "eseek64",
        "getdspace",
        "openM",
        "openR",
        "openRT",
        "qfsize",
        "qfsize64",
        "qlgetz64",
        "qlseek64",
        "qlsize64",
        "qltell64",
    ],

    "ida_enum" : [
        "const_visitor_t",
        "for_all_consts",
        "get_bmask_node",
        "ENUM_FLAGS_FROMTIL",
        "ENUM_FLAGS_GHOST",
        "ENUM_FLAGS_WIDTH",
    ],

    "ida_expr" : [
        "call_idc_method",
        "call_script_method",
        "compile_script_file",
        "compile_script_func",
        "extlang_call_method_exists",
        "extlang_compile_file_exists",
        "extlang_run_statements_exists",
        "extlang_set_attr_exists",
        "extlang_unload_procmod",
        "get_extlang_fileext",
        "get_idcpath",
        "install_extlang",
        "remove_extlang",
        "run_statements",
        "select_extlang",
        "VarAssign",
        "find_extlang_by_ext",
        "find_extlang_by_name",
        "_IDCFUNC_CB_T",
        "call_idc_func__",
    ],

    "ida_fixup" : [
        "FIXUP_MASK",
        "FIXUP_SELFREL",
        "FIXUP_UNUSED",
        "FIXUP_VHIGH",
        "FIXUP_VLOW",
        "get_fixup_base",
        "get_fixup_extdef_ea",
        "get_fixup_segdef_sel",
        "set_custom_fixup_ex",
        "set_fixup_ex",
    ],

    "ida_frame" : [
        "add_stkvar2",
        "add_stkvar3",
    ],

    "ida_funcs" : [
        "a2funcoff",
        "get_sig_filename",
        "std_gen_func_header",
        "apply_idasgn",
    ],

    "ida_gdl" : [
        "display_complex_call_chart",
        "display_flow_graph",
        "display_simple_call_chart",
        "ida_area",
    ],

    "ida_graph" : [
        "pyg_add_command",
    ],

    "ida_hexrays" : [
        "add_custom_viewer_popup_item",
        "vcall_helper",
        "vcreate_helper",
    ],

    "ida_ida" : [
        "IDAPLACE_HEXDUMP",
        "LFLG_UNUSED",
        "PREF_VARMARK",
        "text_options_t",
        "dto_copy_from_inf",
        "dto_copy_to_inf",
        "dto_init",
    ],

    "ida_idd" : [
        "BPT_OLD_EXEC",
        "idd_opinfo_old_t",
    ],

    "ida_idp" : [
        "create_custom_fixup",
        "deleting_enum_const",
        "enum_const_created",
        "enum_const_deleted",
        "gen_abssym",
        "gen_comvar",
        "gen_extern",
        "gen_spcdef",
        "intel_data",
        "ph_get_high_fixup_bits",
    ],

    "ida_kernwin" : [
        "CHOOSER_HOTKEY",
        "add_chooser_command",
        "add_menu_item",
        "add_output_popup",
        "choose2_add_command",
        "choose_choose",
        "create_ea_viewer",
        "create_tform",
        "del_menu_item",
        "enable_menu_item",
        "get_tform_idaview",
        "obsolete_msg_popup",
        "obsolete_view_popup",
        "py_menu_item_callback",
        "pyscv_add_popup_menu",
        "pyscv_clear_popup_menu",
        "set_menu_item_icon",
        "vumsg",
        "choose_enter",
        "choose_getl",
        "choose_segreg",
        "choose_sizer",
        "askfile2_cv",
        "vaskqstr",

        # ctypes vars
        "DEFAULT_MODE",
        "RTLD_GLOBAL",
        "RTLD_LOCAL",
    ],

    "ida_lines" : [
        "ExtraFree",
        "MakeBorder",
        "MakeLine",
        "MakeNull",
        "MakeSolidBorder",
        "gen_cmt_line",
        "gen_collapsed_line",
        "generate_big_comment",
        "generate_many_lines",
        "printf_line",
    ],

    "ida_loader" : [
        "load_loader_module",
    ],

    "ida_moves" : [
        "CURLOC_SISTACK_ITEMS",
        "UNHID_AREA",
        "curloc",
        "location_t",
    ],

    "ida_nalt" : [
        "SWI_SHIFT1",
        "del_jumptable_info",
        "get_auto_plugins",
        "get_jumptable_info",
        "ids_array",
        "jumptable_info_t",
        "set_auto_plugins",
        "set_jumptable_info",
        "switch_info_t_get_regdtyp",
        "switch_info_t_set_regdtyp",
        "switch_info_ex_t_set_flags2",
        "switch_info_ex_t_get_flags2",
    ],

    "ida_name" : [
        "append_struct_fields2",
        "gen_name_decl",
    ],

    "ida_netnode" : [
        "NNBASE_IOERR",
        "NNBASE_OK",
        "NNBASE_PAGE16",
        "NNBASE_REPAIR",
    ],

    "ida_pro" : [
        "convert_encoding", # wasn't usable (bytevec_t not exposed)
        "init_process",
        "qsplitpath", # wasn't usable (char **)
        "replace_tabs", # wasn't usable (wasn't returning the string)
        "vinterr", # wasn't usable (va_list)
        "expand_argv",
        "free_argv",
        "qwait",
        "qwait_timed",
        "ida_false_type", # traits
        "ida_true_type", # traits
    ],

    "ida_queue" : [
        "QueueMark",
    ],

    "ida_segment" : [
        "std_gen_segm_footer",
    ],

    "ida_srarea" : [
        "get_srarea",
        "get_srareas_qty",
        "getn_srarea",
        "segreg_t",
    ],

    "ida_strlist" : [
        "set_strlist_options",
    ],

    "ida_struct" : [
        "get_member_ti",
        "set_member_ti",
        "get_or_guess_member_type",
    ],

    "ida_typeinf" : [
        "ARGLOC_REG",
        "ARGLOC_REG2",
        "BAD_VARLOC",
        "append_complex_n",
        "append_da",
        "append_de",
        "append_dt",
        "append_name",
        "append_varloc",
        "apply_once_type_and_name",
        "apply_type2",
        "apply_type_to_stkarg",
        "build_array_type",
        "build_func_type",
        "build_func_type2",
        "build_funcarg_info",
        "calc_argloc_info",
        "calc_func_nargs",
        "calc_max_children_qty",
        "calc_max_number_of_children",
        "calc_varloc_info",
        "check_skip_type",
        "convert_argloc_to_varloc",
        "convert_varloc_to_argloc",
        "create_numbered_type_reference",
        "extract_and_convert_old_argloc",
        "extract_old_argloc",
        "for_all_types",
        "func_type_info_t",
        "funcarg_info_t",
        "get_argloc_r1",
        "get_argloc_r2",
        "get_complex_n",
        "get_enum_base_type",
        "get_func_cc",
        "get_func_cvtarg_map",
        "get_func_nargs",
        "get_func_rettype",
        "get_funcarg_size",
        "get_idainfo_by_type2",
        "get_name_of_named_type",
        "get_ptr_object_size",
        "get_referred_ordinal",
        "get_scattered_varloc",
        "get_spoil_cnt",
        "get_stkarg_offset",
        "get_strmem",
        "get_strmem2",
        "get_strmem_by_name",
        "get_strmem_t",
        "get_tilpath",
        "get_type_sign",
        "get_type_size0",
        "guess_func_tinfo",
        "is_castable2",
        "is_reg2_argloc",
        "is_reg_argloc",
        "cleanup_varloc",
        "copy_varloc",
        "is_resolved_type_struni",
        "is_restype_array",
        "is_restype_bitfld",
        "is_restype_complex",
        "is_restype_const",
        "is_restype_floating",
        "is_restype_func",
        "is_restype_ptr",
        "is_restype_union",
        "is_stack_argloc",
        "is_type_only_size",
        "is_type_resolvable",
        "is_type_scalar2",
        "is_type_unk",
        "is_type_void_obsolete",
        "is_type_voiddef",
        "is_valid_full_type",
        "make_array_type",
        "make_old_argloc",
        "parse_types2",
        "print_type_to_qstring",
        "remove_type_pointer",
        "rename_named_type",
        "replace_subtypes",
        "replace_subtypes2",
        "resolve_complex_type2",
        "set_complex_n",
        "set_named_type64",
        "set_scattered_varloc",
        "set_spoils",
        "skip_spoiled_info",
        "skip_varloc",
        "split_old_argloc",
        "til2idb",
        "type_mapper_t",
        "type_pair_t",
        "type_pair_vec_t",
        "type_visitor_t",
        "valstrs_deprecated2_t",
        "valstrs_deprecated_t",
    ],

    "ida_ua" : [
        "OutBadInstruction",
        "OutChar",
        "OutImmChar",
        "OutLine",
        "OutLong",
        "OutMnem",
        "OutValue",
        "cmd",
        # can't simulate those; they rely on cmd
        "dataSeg",
        "dataSeg_op",
        "dataSeg_opreg",
        "init_output_buffer",
        "out_addr_tag",
        "out_colored_register_line",
        "out_keyword",
        "out_line",
        "out_long",
        "out_name_expr",
        "out_one_operand",
        "out_register",
        "out_symbol",
        "out_tagoff",
        "out_tagon",
        "py_get_global_cmd_link",
        "term_output_buffer",
        "ua_ana0",
        "ua_code",
        "ua_outop",
        "ua_outop2",
        "ua_next_byte",
        "ua_next_word",
        "ua_next_long",
        "ua_next_qword",

        # these guys are now handled by SWiG (no more c-link stuff.)
        "insn_t_assign",
        "insn_t_create",
        "insn_t_destroy",
        "insn_t_get_auxpref",
        "insn_t_get_canon_feature",
        "insn_t_get_canon_mnem",
        "insn_t_get_cs",
        "insn_t_get_ea",
        "insn_t_get_flags",
        "insn_t_get_insnpref",
        "insn_t_get_ip",
        "insn_t_get_itype",
        "insn_t_get_op_link",
        "insn_t_get_segpref",
        "insn_t_get_size",
        "insn_t_is_canon_insn",
        "insn_t_set_auxpref",
        "insn_t_set_cs",
        "insn_t_set_ea",
        "insn_t_set_flags",
        "insn_t_set_insnpref",
        "insn_t_set_ip",
        "insn_t_set_itype",
        "insn_t_set_segpref",
        "insn_t_set_size",
        "op_t_assign",
        "op_t_create",
        "op_t_destroy",
        "op_t_get_addr",
        "op_t_get_dtyp",
        "op_t_get_flags",
        "op_t_get_n",
        "op_t_get_offb",
        "op_t_get_offo",
        "op_t_get_reg_phrase",
        "op_t_get_specflag1",
        "op_t_get_specflag2",
        "op_t_get_specflag3",
        "op_t_get_specflag4",
        "op_t_get_specval",
        "op_t_get_type",
        "op_t_get_value",
        "op_t_set_addr",
        "op_t_set_dtyp",
        "op_t_set_flags",
        "op_t_set_n",
        "op_t_set_offb",
        "op_t_set_offo",
        "op_t_set_reg_phrase",
        "op_t_set_specflag1",
        "op_t_set_specflag2",
        "op_t_set_specflag3",
        "op_t_set_specflag4",
        "op_t_set_specval",
        "op_t_set_type",
        "op_t_set_value",
    ],

    "idc" : [
        "ida_srarea",
        "ASCSTR_LAST",
        "FIXUP_MASK",
        "GetOpnd",
        "MakeCustomDataEx",
        "SW_MICRO",
        "SetFlags",
        "SetHiddenArea",
        "FF_VAR",
        "INFFL_LZERO",
        "INF_WIDE_HIGH_BYTE_FIRST",
        "INF_ABINAME",
        "INF_ASCIIFLAGS",
        "INF_ASCIIPREF",
        "INF_ASCIISERNUM",
        "INF_ASCIIZEROES",
        "INF_ASCII_BREAK",
        "INF_ASSUME",
        "INF_AUTO",
        "INF_BEGIN_EA",
        "INF_CHECKARG",
        "INF_CORESTART",
        "INF_ENTAB",
        "INF_FCORESIZ",
        "INF_MF",
        "INF_NAMELEN",
        "INF_NULL",
        "INF_ORG",
        "INF_PACKBASE",
        "INF_PREFSEG",
        "INF_SHOWAUTO",
        "INF_SHOWBADS",
        "INF_SHOWPREF",
        "INF_START_AF",
        "INF_VOIDS",
        "REF_VHIGH",
        "REF_VLOW",
        "_invoke_idc_setprm",
        "byteValue",
        "isFop0",
        "isFop1",
        "isVar",
        "Tabs",
        "o_fpreg_arm",
        "INF_TRIBYTE_ORDER",
        "TRIBYTE_123",
        "TRIBYTE_132",
        "TRIBYTE_213",
        "TRIBYTE_231",
        "TRIBYTE_312",
        "TRIBYTE_321",
        "INF_LPREFIX",
        "INF_LPREFIXLEN",
    ],
}

for modname in sorted(api_695.keys()):
    m6 = api_695[modname]
    new_modname = modname
    m7 = api_700[renamed_modules.get(modname, modname)]
    for symbol in m6:
        symbol_root = symbol
        params = ""
        paren_idx = symbol_root.find("(")
        if paren_idx > -1:
            symbol_root, params = symbol_root[0:paren_idx], symbol_root[paren_idx:]
        removed_set = removed_symbols.get(modname, [])
        if symbol_root in removed_set:
            continue
        renamed_set = renamed_symbols.get(modname, {})
        if symbol_root in renamed_set.get("TODO", []):
            continue
        target_symbol = renamed_set.get(symbol_root, symbol_root)
        if target_symbol not in m7:
            # try looking for a full prototype then
            target_symbol = renamed_set.get(symbol, symbol)
            if target_symbol not in m7:
                add = ""
                is_redef = False
                if params:
                    # search for something that might correspond
                    x = "%s(" % symbol_root
                    for s in m7:
                        if s.startswith(x):
                            # print ("Candidate for '%s': '%s'" % (x, s))
                            if s.endswith("bc695redef"):
                                is_redef = True # symbol was redefined, and marked as such. We assume we know what we're doing
                                break
                            else:
                                add = " => %s" % s
                if not is_redef:
                    print("Missing: '%s.%s'%s" % (modname, symbol, add))
