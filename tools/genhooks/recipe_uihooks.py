
recipe = {
    "null" : {"ignore" : True},
    "last" : {"ignore" : True},
    "gen_idanode_text" : {"ignore" : True}, # text_t & friends not exposed

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
    "broadcast" : {"ignore" : True},

    "preprocess_action" : {
        "return" : {
            "type" : "int",
            "retexpr" : "return 0",
        }
    },
    "populating_widget_popup" : {
        "params" : {
            "ctx" : {
                "default" : "nullptr",
            },
        },
    },
    "finish_populating_widget_popup" : {
        "params" : {
            "ctx" : {
                "default" : "nullptr",
            },
        },
    },
    "create_desktop_widget" : {
        "params" : {
            "cfg" : {
                "type" : "const jobj_wrapper_t &",
                "convertor" : "UI_Hooks::wrap_widget_cfg",
                "convertor_pass_args" : True,
            },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "UI_Hooks::handle_create_desktop_widget_output",
         }
    },
    "get_widget_config" : {
        "params" : {
            "cfg" : {
                "ignore" : True,
            },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "UI_Hooks::handle_widget_cfg_output",
            "convertor_pass_args" : True,
        },
    },
    "set_widget_config" : {
        "params" : {
            "cfg" : {
                "type" : "jobj_wrapper_t",
                "convertor" : "UI_Hooks::wrap_widget_cfg",
                "convertor_pass_args" : True,
            },
        },
    },
    "database_closed" : {
        "params" : {
            "reserved" :
            {
                "suppress_for_call" : True,
                "qnotused" : True,
            },
        },
    },
}

default_rtype = "void"
