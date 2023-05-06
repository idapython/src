
recipe = {
    "stkpnts" : {
        "params" : {
            "stkpnts" : { "rename" : "_sps", },
        },
    },
    "create_hint" : {
        "params" : {
            "hint" : { "suppress_for_call" : True, },
            "important_lines" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "Hexrays_Hooks::handle_create_hint_output",
            "convertor_pass_args" : True,
        }
    },
    "build_callinfo" : {
        "params" : {
            "callinfo" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "Hexrays_Hooks::handle_build_callinfo_output",
            "convertor_pass_args" : True,
        }
    },
}

default_rtype = "int"
