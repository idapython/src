from __future__ import with_statement
from __future__ import print_function

import sys, optparse, re, pprint

class TextStream:
    def __init__(self, text):
        self.text = text
        self.point = 0
        self.maxpoint = len(self.text)
        self.line_nr = 0
        self.char_nr = 0

    def line(self):
        pt = self.point
        self.advance_to_newline()
        return self.text[pt : self.point]

    def char(self):
        c, self.point = self.text[self.point], self.point + 1
        if c == '\n':
            self.line_nr += 1
            self.char_nr = 0
        return c

    def advance_to_newline(self):
        p = self.point
        while self.text[p] != '\n':
            p += 1
        p += 1
        self.line_nr += 1
        self.char_nr = 0
        self.point = p

    def empty(self):
        return self.point >= self.maxpoint


def check_cpp(opts):

    api_contents = {
        "functions" : []
        }

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
        "_wrap_tinfo_t_deserialize__SWIG_2" : {
            "mustcall" : "tinfo_t_deserialize__SWIG_2",
            },
        "_wrap_get_bpt_group" : {
            "mustcall" : "IDAPyStr_FromUTF8AndSize",
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
            "mustcall" : "IDAPyBytes_AsString",
        },
        "_wrap_error__varargs__" : {
            "nullptrcheck" : 1,
            "mustcall" : "IDAPyBytes_AsString",
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
            "mustcall" : ["cfunc_t___str__", "IDAPyStr_FromUTF8AndSize"],
            },
        "_wrap_cfunc_t___str__" : {
            "mustcall" : ["cfunc_t___str__", "IDAPyStr_FromUTF8AndSize"],
            },
        "_wrap_hexrays_failure_t_desc" : {
            "mustcall" : "IDAPyStr_FromUTF8AndSize",
            },
        "_wrap_vd_failure_t_desc" : {
            "mustcall" : "IDAPyStr_FromUTF8AndSize",
            },
        "_wrap_create_field_name" : {
            "mustcall" : "IDAPyStr_FromUTF8AndSize",
            },
        "delete_qrefcnt_t_Sl_cfunc_t_Sg_" : {
            "mustcall" : "hexrays_deregister_python_clearable_instance",
            },
        "_wrap__decompile" : {
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
    if opts.with_hexrays:
        functions_coherence.update(functions_coherence_hexrays)

    # Mark all functions as not-spotted.
    for fname in functions_coherence.keys():
        chk = functions_coherence[fname]
        chk["spotted"] = False

    def dbg(msg):
        if opts.verbose:
            print("DEBUG: %s" % msg)

    def is_fundecl(line):
        if len(line) <= 2:
            return False
        if line[0:1].isspace():
            return False
        if line[len(line)-1:] != "{":
            return False
        if line.find("(") == -1 or line.find(")") == -1:
            return False
        return True

    def collect_funbody_lines(ts):
        pt = ts.point
        braces_cnt = 1
        while True:
            c = ts.char()
            if c == "{":
                braces_cnt = braces_cnt + 1
            elif c == "}":
                braces_cnt = braces_cnt - 1
                if braces_cnt == 0:
                    break;
            # TODO: Skip strings!
        return ts.text[pt : ts.point].split("\n")

    api_fname_regex = re.compile(".*PyObject \\*_wrap_([^\\(]*)\\(.*\\).*")

    KICKME_functions_lines = {}

    # Read and go through lines
    for one_file in opts.files.split(","):
        with open(one_file, "r") as f:
            raw = f.read()
        # ensure we have improved director out type reporting
        if raw.find("""in output value of type '""int""'");""") > -1:
            raise Exception("Director output value type reporting doesn't appear to be patched")
        ts = TextStream(raw)

        # Process lines
        while not ts.empty():
            line = ts.line().rstrip()
            # dbg("Line: '%s'" % line)

            if is_fundecl(line):
                # dbg("Entering function (from line %d: '%s')" % (ts.line_nr, line))
                funstart = line
                match = api_fname_regex.match(funstart)
                if match:
                    fname = match.group(1)
                    api_contents["functions"].append(fname)
                funlines = collect_funbody_lines(ts)
                KICKME_functions_lines[fname] = funlines
                # Do we care about this function?
                check_for = None
                for fname in functions_coherence.keys():
                    if funstart.find(fname + "(") > -1:
                        check_for = fname
                        break
                if check_for:
                    dbg("Checking function at line %d: '%s'" % (ts.line_nr, check_for))
                    chk = functions_coherence[check_for]
                    chk["spotted"] = True
                    def look_for_stuff(stuff, is_funcall, lookForPresence=True):
                        if isinstance(stuff, str):
                            stuff = [stuff]
                        for bit in stuff:
                            found = False
                            bit_pat = ("%s(" % bit) if is_funcall else bit
                            dbg("Thing to look for: '%s'" % bit_pat)
                            for funline in funlines:
                                # dbg("Testing line: '%s'" % funline)
                                if funline.find(bit_pat) > -1:
                                    found = True
                                    break
                            if lookForPresence:
                                if not found:
                                    raise Exception("Couldn't find '%s', from function '%s' (lines: %s)" %
                                                    (bit_pat, check_for, "\n".join([""] + funlines)))
                            else:
                                if found:
                                    raise Exception("Did find unwanted '%s', from function '%s' (lines: %s)" %
                                                    (bit_pat, check_for, "\n".join([""] + funlines)))

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
    if opts.report_contents:

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
        ]
        to_report = sorted(filter(
            lambda fn: fn not in ignorable_functions,
            api_contents["functions"]))

        # NB: we use "wb" here so that the endlines
        # are written as-is, in Unix format
        # and so 'diff' does not report bogus changes
        # against the file from repository
        with open(opts.report_contents, "w") as f:
            f.write(pprint.pformat({"functions" : to_report}))

    # import pickle
    # with open("/tmp/funlines.last", "wb") as fo:
    #     pickle.dump(KICKME_functions_lines, fo)


def check_python(opts):
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
        "processor_t" : { "mustinherit" : "ida_idaapi.pyidc_opaque_object_t" },
        "py_clinked_object_t" : { "mustinherit" : "pyidc_opaque_object_t" },
        "segm_move_infos_t" : { "mustinherit" : "segm_move_info_vec_t" },
        "simpleline_place_t" : { "mustinherit" : "place_t" },
        "structplace_t" : { "mustinherit" : "place_t" },
        "textctrl_info_t" : { "mustinherit" : "ida_idaapi.py_clinked_object_t" },
        "udt_type_data_t" : { "mustinherit" : "udtmembervec_t" },

        # Just look for the presence of those things
        "BADNODE" : {},
    }

    types_coherence_hexrays = {
        "DecompilationFailure" : { "mustinherit" : "Exception" },
        "carg_t" : { "mustinherit" : "cexpr_t" },
        "carglist_t" : { "mustinherit" : "qvector_carg_t" },
        "cblock_t" : { "mustinherit" : "qlist_cinsn_t" },
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
        # "vivl_t" : { "mustinherit" : "ivl_t" },
    }

    types_coherence = types_coherence_base.copy()
    if opts.with_hexrays:
        types_coherence.update(types_coherence_hexrays)

    # Mark all types as not-spotted.
    for tname in types_coherence.keys():
        chk = types_coherence[tname]
        chk["spotted"] = False

    class_re = re.compile("^class ([a-zA-Z0-9_]*)\\(([a-zA-Z0-9_\\.]*)\\):")
    var_re = re.compile("^([a-zA-Z0-9_]*) = .*")
    for one_file in opts.python_files.split(","):
        with open(one_file, "r") as f:
            ts = TextStream(f.read())

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

    p = optparse.OptionParser(description='Check the generated idaapi_include.cpp file')
    p.add_option('-v', "--verbose", dest="verbose", action="store_true")
    p.add_option('-i', "--input", dest="files", type="string")
    p.add_option('-p', "--python-input", dest="python_files", type="string")
    p.add_option('-x', "--with-hexrays", dest="with_hexrays", action="store_true")
    p.add_option('-r', "--report-contents", dest="report_contents", type="string")
    opts, _ = p.parse_args(sys.argv[1:])

    if not opts.files or not opts.python_files:
        p.print_help()
        sys.exit(1)

    check_cpp(opts)
    check_python(opts)
