

recipe = {
    "last_cb_before_debugger" : {"ignore" : True},
    "last_cb_before_type_callbacks" : {"ignore" : True},
    "get_operand_info" : {"ignore" : True},
    "obsolete_get_operand_info" : {"ignore" : True},
    "loader_elf_machine" : {"ignore" : True},
    "custom_ana" : {
        "return" : {
            "type" : "bool",
            "default" : "false",
            "convertor" : "IDP_Hooks::bool_to_cmdsize",
        }
    },
    "custom_out" : {
        "return" : {
            "type" : "bool",
            "default" : "false",
            "convertor" : "IDP_Hooks::bool_to_2or0",
        }
    },
    "custom_emu" : {
        "return" : {
            "type" : "bool",
            "default" : "false",
            "convertor" : "IDP_Hooks::bool_to_2or0",
        }
    },
    "custom_outop" : {
        "params" : {
            "op" : {
                "type" : "PyObject *",
                "clinked" : {
                    "module_define" : "S_IDA_UA_MODNAME",
                    "class_define" : "S_PY_OP_T_CLSNAME",
                },
            },
        },
        "return" : {
            "type" : "bool",
            "default" : "false",
            "convertor" : "IDP_Hooks::bool_to_2or0",
        }
    },
    "custom_mnem" : {
        "params" : {
            "buf"     : { "suppress_for_call" : True, },
            "bufsize" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_custom_mnem_output",
            "convertor_pass_args" : True,
        }
    },
    "rename" : {
        "params" : {
            "flags" : {
                "suppress_for_call" : True,
                "qnotused" : True,
            },
        },
    },
    "savebase" : {
        "return" : {
            "type" : "void"
        }
    },
    "assemble" : {
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_assemble_output",
            "convertor_pass_args" : True,
        },
        "params" : {
            "bin" : {
                "suppress_for_call" : True,
            },
        },
    },
    "decorate_name3" : {
        "params" : {
            "cc" : {
                "type" : "int",
                "convertor" : "IDP_Hooks::cm_t_to_int",
            },
            "outbuf" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_decorate_name3_output",
            "convertor_pass_args" : True,
        }
    },
    "get_reg_name" : {
        "params" : {
            "buf"     : { "suppress_for_call" : True, },
            "bufsize" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_get_reg_name_output",
            "convertor_pass_args" : True,
        }
    },
}
