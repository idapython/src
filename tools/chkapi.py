from __future__ import with_statement
from __future__ import print_function

import sys
import os
import argparse
import re
import pprint

mydir, _ = os.path.split(__file__)
if mydir not in sys.path:
    sys.path.append(mydir)

import wrapper_utils

def check_cpp(args):

    functions_coherence_base = {
        #
        # qstrvec_t: Specialized, internal, clink'ed object.
        #
        "_wrap_qstrvec_t_assign" : {
            "mustcall" : "qstrvec_t_assign"
        },
        "_wrap_qstrvec_t_addressof" : {
            "mustcall" : "qstrvec_t_addressof"
        },
        "_wrap_qstrvec_t_set" : {
            "mustcall" : "qstrvec_t_set"
        },
        "_wrap_qstrvec_t_from_list" : {
            "mustcall" : "qstrvec_t_from_list"
        },
        "_wrap_qstrvec_t_size" : {
            "mustcall" : "qstrvec_t_size"
        },
        "_wrap_qstrvec_t_get" : {
            "mustcall" : "qstrvec_t_get"
        },
        "_wrap_qstrvec_t_add" : {
            "mustcall" : "qstrvec_t_add"
        },
        "_wrap_qstrvec_t_clear" : {
            "mustcall" : "qstrvec_t_clear"
        },
        "_wrap_qstrvec_t_insert" : {
            "mustcall" : "qstrvec_t_insert"
        },
        "_wrap_qstrvec_t_remove" : {
            "mustcall" : "qstrvec_t_remove"
        },

        #
        # Misc.
        #
        "_wrap_tinfo_t_deserialize__SWIG_1" : {
            "mustcall" : "tinfo_t_deserialize__SWIG_1",
        },
        "_wrap_get_bpt_group" : {
            "mustcall" : "_maybe_sized_cstring_result",
        },
        "_wrap_get_ip_val" : {
            "string" : "resultobj = PyLong_FromUnsigned",
        },
        "_wrap_calc_thunk_func_target" : {
            "string" : ["SWIG_Python_AppendOutput", "PyLong_FromUnsigned"],
        },
        "SwigDirector_UI_Hooks::populating_widget_popup" : {
            "string" : "get_callable_arg_count",
        },
        "_wrap_idc_get_local_type" : {
            "mustcall" : "__chkreqidb"
        },
        "_wrap_append_argloc" : {
            "mustcall" : "__chkreqidb"
        },
        "_wrap_is_type_ptr" : {
            "nostring" : "__chkreqidb",
        },

        # "_wrap_get_array_parameters" : {
        #     "string" : "resultobj = PyLong_FromLongLong(result)",
        #     },
        # "_wrap_read_dbg_memory" : {
        #     "string" : "resultobj = PyLong_FromLongLong(result)",
        #     },
        # "_wrap_write_dbg_memory" : {
        #     "string" : "resultobj = PyLong_FromLongLong(result)",
        #     },
        # "_wrap_get_grp_bpts" : {
        #     "string" : "resultobj = PyLong_FromLongLong(result)",
        #     },
        # "_wrap_generic_linput_t_read" : {
        #     "string" : "resultobj = PyLong_FromLongLong(result)",
        #     },
        # "_wrap_linput_buffer_t_read" : {
        #     "string" : "resultobj = PyLong_FromLongLong(result)",
        #     },
        # "_wrap_tag_strlen" : {
        #     "string" : "resultobj = PyLong_FromLongLong(result)",
        #     },
        # "_wrap_get_next_member_idx" : {
        #     "string" : "resultobj = PyLong_FromLongLong(result)",
        #     },
        # "_wrap_get_prev_member_idx" : {
        #     "string" : "resultobj = PyLong_FromLongLong(result)",
        #     },
        "_wrap_guess_tinfo" : {
            "mustcall" : "PyW_GetNumber",
        },
        "_wrap_IDP_Hooks_ev_adjust_refinfo" : {
            "string" : "fixup_data_t",
        },
        # char[ANY] out typemap
        "_wrap_idainfo_tag_get" : {
            "nostring" : " --size;",
        },

        "_wrap_warning__varargs__" : {
            "nullptrcheck" : 1, # 1st arg
            "mustcall" : "PyUnicode_as_qstring",
        },
        "_wrap_error__varargs__" : {
            "nullptrcheck" : 1,
            "mustcall" : "PyUnicode_as_qstring",
        },
        "_wrap_tag_remove" : {
            "nullptrcheck" : 1,
        },
        "_wrap_compile_idc_file" : {
            "nullptrcheck" : 1,
        },
        "_wrap_compile_idc_text" : {
            "nullptrcheck" : 1,
        },
        "_wrap_get_member_size" : {
            "nullptrcheck" : 1,
        },
        "_wrap_load_debugger" : {
            "string" : ["SWIG_PYTHON_THREAD_BEGIN_ALLOW", "SWIG_PYTHON_THREAD_END_ALLOW"],
        },
        "_wrap_AssembleLine" : {
            "nullptrcheck" : 5,
        },

        "_wrap_get_opinfo" : {
            "string" : ["Py_XDECREF(resultobj)", "Py_INCREF(resultobj)"],
        },

        "_wrap_file2base" : {
            "nostring" : ["SWIGTYPE_p_qoff64_t", "qoff64_t *"],
        },

    }

    functions_coherence_hexrays = {
        "_wrap_cfuncptr_t___str__" : {
            "mustcall" : ["cfunc_t___str__", "PyUnicode_FromStringAndSize"],
        },
        "_wrap_cfunc_t___str__" : {
            "mustcall" : ["cfunc_t___str__", "PyUnicode_FromStringAndSize"],
        },
        "_wrap_hexrays_failure_t_desc" : {
            "mustcall" : "PyUnicode_FromStringAndSize",
        },
        "_wrap_vd_failure_t_desc" : {
            "mustcall" : "PyUnicode_FromStringAndSize",
        },
        "_wrap_create_field_name" : {
            "mustcall" : "PyUnicode_FromStringAndSize",
        },
        "delete_qrefcnt_t_Sl_cfunc_t_Sg_" : {
            "mustcall" : "hexrays_deregister_python_clearable_instance",
        },
        "_wrap_decompile" : {
            "mustcall" : "hexrays_register_python_clearable_instance",
        },
        "_wrap_vdui_t_cfunc_get" : {
            "mustcall" : "hexrays_register_python_clearable_instance",
        },
        "delete_cexpr_t" : {
            "mustcall" : "hexrays_deregister_python_clearable_instance",
        },
        "delete_cinsn_t" : {
            "mustcall" : "hexrays_deregister_python_clearable_instance",
        },
        " delete_cblock_t" : {
            "mustcall" : "hexrays_deregister_python_clearable_instance",
        },
        "new_cexpr_t__SWIG_0" : {
            "mustcall" : "hexrays_register_python_clearable_instance",
        },
        "new_cexpr_t__SWIG_1" : {
            "mustcall" : "hexrays_register_python_clearable_instance",
        },
        "new_cinsn_t__SWIG_0" : {
            "mustcall" : "hexrays_register_python_clearable_instance",
        },
        "new_cinsn_t__SWIG_1" : {
            "mustcall" : "hexrays_register_python_clearable_instance",
        },
        "new_carg_t" : {
            "mustcall" : "hexrays_register_python_clearable_instance",
        },
        "delete_carg_t" : {
            "mustcall" : "hexrays_deregister_python_clearable_instance",
        },
        "*new_cblock_t" : {
            "mustcall" : "hexrays_register_python_clearable_instance",
        },
        "_wrap_boundaries_find" : {
            "nostring" : "SWIGTYPE_p_p_cinsn_t",
        },
        "mba_t_serialize" : {
            "string" : "bytes_container typemap(argout) (bytevec_t &vout)",
            "mustcall" : "_sized_binary_result",
        },

        #
        # qvector<simpleline_t>
        #
        "_wrap_strvec_t___len__" : {
            "mustcall" : "qvector_Sl_simpleline_t_Sg____len__",
        },
        "_wrap_strvec_t___setitem__" : {
            "mustcall" : "qvector_Sl_simpleline_t_Sg____setitem__",
        },
        "_wrap_strvec_t___getitem__" : {
            "mustcall" : "qvector_Sl_simpleline_t_Sg____getitem__",
        },
        #
        # vdui_t::cfunc
        #
        "_wrap_vdui_t_cfunc_get" : {
            "string" : "SWIGTYPE_p_qrefcnt_tT_cfunc_t_t",  # proper typemap must be used
        },
    }

    functions_coherence = functions_coherence_base.copy()
    if args.with_hexrays:
        functions_coherence.update(functions_coherence_hexrays)

    # Mark all functions as not-spotted.
    for fname in functions_coherence.keys():
        chk = functions_coherence[fname]
        chk["spotted"] = False

    def verb(msg):
        if args.verbose:
            print("DEBUG: %s" % msg)

    api_functions_names = []
    for one_file in args.cpp_input.split(","):
        verb("Handling file: '%s'" % one_file)
        parser = wrapper_utils.cpp_wrapper_file_parser_t(args)
        functions = parser.parse(one_file)

        # ensure we have improved director out type reporting
        if parser.text.find("""in output value of type '""int""'");""") > -1:
            raise Exception("Director output value type reporting doesn't appear to be patched")

        for fname, fdef in functions.items():

            if fdef.api_function_name:
                api_functions_names.append(fdef.api_function_name)

            # Do we care about this function?
            funstart = fdef.contents[0]
            check_for = None
            for fname in functions_coherence.keys():
                if funstart.find(fname + "(") > -1:
                    check_for = fname
                    break

            if check_for:
                verb("Checking function at line %d: '%s'" % (fdef.line_nr, check_for))
                chk = functions_coherence[check_for]
                chk["spotted"] = True
                def look_for_stuff(stuff, is_funcall, lookForPresence=True):
                    if isinstance(stuff, str):
                        stuff = [stuff]
                    for bit in stuff:
                        found = False
                        bit_pat = ("%s(" % bit) if is_funcall else bit
                        verb("Thing to look for: '%s'" % bit_pat)
                        for funline in fdef.contents[1:]:
                            # verb("Testing line: '%s'" % funline)
                            if funline.find(bit_pat) > -1:
                                found = True
                                break
                        if lookForPresence:
                            if not found:
                                raise Exception("Couldn't find '%s', from function '%s' (lines: %s)" %
                                                (bit_pat, check_for, "\n".join(fdef.contents)))
                        else:
                            if found:
                                raise Exception("Did find unwanted '%s', from function '%s' (lines: %s)" %
                                                (bit_pat, check_for, "\n".join(fdef.contents)))

                if "mustcall" in chk:
                    look_for_stuff(chk["mustcall"], True)
                if "string" in chk:
                    look_for_stuff(chk["string"], False)
                if "nostring" in chk:
                    look_for_stuff(chk["nostring"], False, lookForPresence=False)
                if "nullptrcheck" in chk:
                    look_for_stuff('"invalid null pointer " "in method \'" "%s" "\', argument " "%d""' % (
                        fname.replace("_wrap_", "").replace("__varargs__", ""),
                        chk["nullptrcheck"]), False)

    # Ensure all functions were spotted.
    for fname in functions_coherence.keys():
        chk = functions_coherence[fname]
        if not chk["spotted"]:
            raise Exception("Couldn't spot function '%s'" % fname)

    # Report contents
    if args.report_contents:

        ignorable_functions = [
            "citem_t___dbg_get_meminfo",
            "citem_t___dbg_get_registered_kind",
            "compute_func_sig",
            "delete_func_md_t",
            "delete_func_pat_t",
            "extract_func_md",
            "func_md_t_ea_get",
            "func_md_t_ea_set",
            "func_md_t_name_get",
            "func_md_t_name_set",
            "func_md_t_size_get",
            "func_md_t_size_set",
            "func_pat_t_bytes_get",
            "func_pat_t_bytes_set",
            "func_pat_t_relbits_get",
            "func_pat_t_relbits_set",
            "new_func_md_t",
            "new_func_pat_t",
            "DBG_Hooks_dump_state",
            "Hexrays_Hooks_dump_state",
            "IDB_Hooks_dump_state",
            "IDP_Hooks_dump_state",
            "UI_Hooks_dump_state",
            "View_Hooks_dump_state",
        ]
        to_report = sorted(filter(
            lambda fn: fn not in ignorable_functions,
            api_functions_names))

        # NB: we use "wb" here so that the endlines
        # are written as-is, in Unix format
        # and so 'diff' does not report bogus changes
        # against the file from repository
        with open(args.report_contents, "wb") as f:
            f.write(pprint.pformat({"functions" : to_report}).encode("UTF-8"))


def check_python(args):
    types_coherence_base = {
        "func_t" : { "mustinherit" : "ida_range.range_t" },
        "hidden_range_t" : { "mustinherit" : "ida_range.range_t" },
        "qbasic_block_t" : { "mustinherit" : "ida_range.range_t" },
        "regvar_t" : { "mustinherit" : "ida_range.range_t" },
        "segment_t" : { "mustinherit" : "ida_range.range_t" },
        "sreg_range_t" : { "mustinherit" : "ida_range.range_t" },
        "memory_info_t" : { "mustinherit" : "ida_range.range_t" },

        "GraphViewer" : { "mustinherit" : "ida_kernwin.CustomIDAMemo" },
        "IDAViewWrapper" : { "mustinherit" : "CustomIDAMemo" },
        "PyIdc_cvt_int64__" : { "mustinherit" : "pyidc_cvt_helper__" },
        "PyIdc_cvt_refclass__" : { "mustinherit" : "pyidc_cvt_helper__" },
        "_qstrvec_t" : { "mustinherit" : "ida_idaapi.py_clinked_object_t" },
        "argpart_t" : { "mustinherit" : "argloc_t" },
        "cli_t" : { "mustinherit" : "ida_idaapi.pyidc_opaque_object_t" },
        "enumplace_t" : { "mustinherit" : "place_t" },
        "func_type_data_t" : { "mustinherit" : "funcargvec_t" },
        "ida_lowertype_helper_t" : { "mustinherit" : "lowertype_helper_t" },
        "idaplace_t" : { "mustinherit" : "place_t" },
        "insn_t" : { "mustinherit" : "object" },
        "op_t" : { "mustinherit" : "object" },
        "plugin_t" : { "mustinherit" : "pyidc_opaque_object_t" },
        "processor_t" : { "mustinherit" : "IDP_Hooks" },
        "py_clinked_object_t" : { "mustinherit" : "pyidc_opaque_object_t" },
        "segm_move_infos_t" : { "mustinherit" : "segm_move_info_vec_t" },
        "simpleline_place_t" : { "mustinherit" : "place_t" },
        "structplace_t" : { "mustinherit" : "place_t" },
        "textctrl_info_t" : { "mustinherit" : "ida_idaapi.py_clinked_object_t" },
        "udtmembervec_t" : { "mustinherit" : "udtmembervec_template_t" },
        "udt_type_data_t" : { "mustinherit" : "udtmembervec_t" },
        "call_stack_t" : { "mustinherit" : "call_stack_info_vec_t" },
        "abstract_graph_t" : { "mustinherit" : "ida_gdl.gdl_graph_t" },
        "mutable_graph_t" : { "mustinherit" : "abstract_graph_t" },
        "meminfo_vec_t" : { "mustinherit" : "meminfo_vec_template_t" },

        # Just look for the presence of those things
        "BADNODE" : {},
    }

    types_coherence_hexrays = {
        "DecompilationFailure" : { "mustinherit" : "Exception" },
        "carg_t" : { "mustinherit" : "cexpr_t" },
        "carglist_t" : { "mustinherit" : "qvector_carg_t" },
        "cblock_t" : { "mustinherit" : "cinsn_list_t" },
        "ccase_t" : { "mustinherit" : "cinsn_t" },
        "ccases_t" : { "mustinherit" : "qvector_ccase_t" },
        "cdo_t" : { "mustinherit" : "cloop_t" },
        "cexpr_t" : { "mustinherit" : "citem_t" },
        "cfor_t" : { "mustinherit" : "cloop_t" },
        "cfunc_parentee_t" : { "mustinherit" : "ctree_parentee_t" },
        "cif_t" : { "mustinherit" : "ceinsn_t" },
        "cinsn_t" : { "mustinherit" : "citem_t" },
        "cloop_t" : { "mustinherit" : "ceinsn_t" },
        "creturn_t" : { "mustinherit" : "ceinsn_t" },
        "cswitch_t" : { "mustinherit" : "ceinsn_t" },
        "ctree_parentee_t" : { "mustinherit" : "ctree_visitor_t" },
        "cwhile_t" : { "mustinherit" : "cloop_t" },
        "history_item_t" : { "mustinherit" : "ctext_position_t" },
        "history_t" : { "mustinherit" : "qvector_history_t" },
        "lvar_t" : { "mustinherit" : "lvar_locator_t" },
        "lvars_t" : { "mustinherit" : "qvector_lvar_t" },
        "qstring_printer_t" : { "mustinherit" : "vc_printer_t" },
        "vc_printer_t" : { "mustinherit" : "vd_printer_t" },
        "vd_interr_t" : { "mustinherit" : "vd_failure_t" },
        # "casm_t" : { "mustinherit" : "eavec_t" },
        # "vivl_t" : { "mustinherit" : "ivl_t" },
        "ivl_t" : { "mustinherit" : "uval_ivl_t" },
        "ivlset_t" : { "mustinherit" : "uval_ivl_ivlset_t" },
        "simple_graph_t" : { "mustinherit" : "ida_gdl.gdl_graph_t" },
    }

    types_coherence = types_coherence_base.copy()
    if args.with_hexrays:
        types_coherence.update(types_coherence_hexrays)

    # Mark all types as not-spotted.
    for tname in types_coherence.keys():
        chk = types_coherence[tname]
        chk["spotted"] = False

    class_re = re.compile("^class ([a-zA-Z0-9_]*)\\(([a-zA-Z0-9_\\.]*)\\):")
    var_re = re.compile("^([a-zA-Z0-9_]*) = .*")
    for one_file in args.python_input.split(","):
        with open(one_file) as f:
            ts = wrapper_utils.TextStream(f.read())

        while not ts.empty():
            line = ts.line().rstrip()
            match = class_re.match(line)
            if match:
                tname = match.group(1)
                parent = match.group(2)
                if tname in types_coherence.keys():
                    tc = types_coherence[tname]
                    tc["spotted"] = True
                    if "mustinherit" in tc:
                        if tc["mustinherit"] != parent:
                            raise Exception("Type '%s' should inherit from '%s' (and not '%s')" %
                                            (tname, tc["mustinherit"], parent))
            else:
                match = var_re.match(line)
                if match:
                    vname = match.group(1)
                    if vname in types_coherence.keys():
                        tc = types_coherence[vname]
                        tc["spotted"] = True


    # Ensure all types were spotted.
    for tname in types_coherence.keys():
        chk = types_coherence[tname]
        if not chk["spotted"]:
            raise Exception("Couldn't spot type '%s'" % tname)



if __name__ == "__main__":

    p = argparse.ArgumentParser(description='Check the generated idaapi_include.cpp file')
    p.add_argument('-v', "--verbose", action="store_true")
    p.add_argument('-i', "--cpp-input", type=str)
    p.add_argument('-p', "--python-input", type=str)
    p.add_argument('-x', "--with-hexrays", action="store_true")
    p.add_argument('-r', "--report-contents", type=str)
    args = p.parse_args()

    if not args.cpp_input or not args.python_input:
        p.print_help()
        sys.exit(1)

    check_cpp(args)
    check_python(args)
