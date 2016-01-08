from __future__ import with_statement

import sys, optparse, re, pprint

ignorable_api_contents = [
    "qwait"
    ]

class TextStream:
    def __init__(self, text):
        self.text = text
        self.point = 0
        self.maxpoint = len(self.text)
        self.line_nr = 0
        self.char_nr = 0
        self.curline = None

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


if __name__ == "__main__":

    p = optparse.OptionParser(description='Check the generated idaapi_include.cpp file')
    p.add_option('-v', "--verbose", dest="verbose", action="store_true")
    p.add_option('-f', "--file", dest="path", type="string")
    p.add_option('-x', "--with-hexrays", dest="with_hexrays", action="store_true")
    p.add_option('-r', "--report-contents", dest="report_contents", type="string")
    opts, _ = p.parse_args(sys.argv[1:])

    api_contents = {
        "functions" : []
        }

    if not opts.path:
        p.print_help()
        sys.exit(1)

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
        "_wrap_areacb_t_get_type" : {
            "mustcall" : "get_type",
            },
        "_wrap_tinfo_t_deserialize__SWIG_2" : {
            "mustcall" : "tinfo_t_deserialize__SWIG_2",
            },
        "_wrap_get_bpt_group" : {
            "mustcall" : "PyString_FromStringAndSize",
            },
        "_wrap_get_jumptable_info" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_get_array_parameters" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_read_dbg_memory" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_write_dbg_memory" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_get_grp_bpts" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_generic_linput_t_read" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_generic_linput64_t_read64" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_linput_buffer_t_read" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_get_ptr_object_size" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_tag_strlen" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_get_next_member_idx" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        "_wrap_get_prev_member_idx" : {
            "string" : "resultobj = PyLong_FromLongLong(result)",
            },
        # char[ANY] out typemap
        "_wrap_idainfo_tag_get" : {
            "nostring" : " --size;",
            },
        # char[ANY] varout typemap
        "Swig_var_database_idb_get" : {
            "nostring" : " --size;",
            },
        }

    functions_coherence_hexrays = {
        "_wrap_cfuncptr_t___str__" : {
            "mustcall" : ["cfunc_t___str__", "PyString_FromStringAndSize"],
            },
        "_wrap_cfunc_t___str__" : {
            "mustcall" : ["cfunc_t___str__", "PyString_FromStringAndSize"],
            },
        "_wrap_hexrays_failure_t_desc" : {
            "mustcall" : "PyString_FromStringAndSize",
            },
        "_wrap_vd_failure_t_desc" : {
            "mustcall" : "PyString_FromStringAndSize",
            },
        "_wrap_create_field_name" : {
            "mustcall" : "PyString_FromStringAndSize",
            },
        "delete_qrefcnt_t_Sl_cfunc_t_Sg_" : {
            "mustcall" : "hexrays_deregister_python_cfuncptr_t_instance",
            },
        "_wrap__decompile" : {
            "mustcall" : "hexrays_register_python_cfuncptr_t_instance",
            },
        "_wrap_vdui_t_cfunc_get" : {
            "mustcall" : "hexrays_register_python_cfuncptr_t_instance",
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

    # Read and go through lines
    with open(opts.path, "r") as f:
        ts = TextStream(f.read())

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

    # Process lines
    STATE_UNKNOWN = 0
    STATE_IN_FUN = 1
    state = STATE_UNKNOWN
    while not ts.empty():
        line = ts.line().rstrip()
        # dbg("Line: '%s'" % line)
        if is_fundecl(line):
            # dbg("Entering function (from line %d: '%s')" % (ts.line_nr, line))
            state = STATE_IN_FUN
            funstart = line
            match = api_fname_regex.match(funstart)
            if match:
                fname = match.group(1)
                if fname not in ignorable_api_contents:
                    api_contents["functions"].append(fname)
            funlines = collect_funbody_lines(ts)
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
                def look_for_stuff(stuff, isFuncall, lookForPresence=True):
                    if isinstance(stuff, str):
                        stuff = [stuff]
                    for bit in stuff:
                        found = False
                        bit_pat = ("%s(" % bit) if isFuncall else bit
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

    # Ensure all functions were spotted.
    for fname in functions_coherence.keys():
        chk = functions_coherence[fname]
        if not chk["spotted"]:
            raise Exception("Couldn't spot function '%s'" % fname)

    # Report contents
    if opts.report_contents:
        # NB: we use "wb" here so that the endlines
        # are written as-is, in Unix format
        # and so 'diff' does not report bogus changes
        # against the file from repository
        with open(opts.report_contents, "wb") as f:
            api_contents["functions"].sort()
            f.write(pprint.pformat(api_contents))

