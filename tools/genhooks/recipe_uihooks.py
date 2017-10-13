
recipe = {
    "null" : {"ignore" : True},
    "last" : {"ignore" : True},
    "gen_idanode_text" : {"ignore" : True}, # text_t & friends not exposed

    "debugger_menu_change" : {
        "return" : {
            "type" : "int",
            "retexpr" : "return 1",
        }
    },
    "get_ea_hint" : {
        "params" : {
            "buf" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "UI_Hooks::handle_get_ea_hint_output",
            "convertor_pass_args" : True,
        }
    },
    "get_item_hint" : {
        "params" : {
            "hint"            : { "suppress_for_call" : True, },
            "important_lines" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "UI_Hooks::handle_hint_output",
            "convertor_pass_args" : True,
        }
    },
    "get_custom_viewer_hint" : {
        "params" : {
            "hint"            : { "suppress_for_call" : True, },
            "important_lines" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "UI_Hooks::handle_hint_output",
            "convertor_pass_args" : True,
        }
    },

    "genfile_callback" : {"ignore" : True},
    "idp_event" : {"ignore" : True},
    "refresh_choosers" : {"ignore" : True},
    "load_dbg_dbginfo" : {"ignore" : True},
}
