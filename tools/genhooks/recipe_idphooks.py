

recipe = {
    "ev_last_cb_before_debugger" : {"ignore" : True},
    "ev_last_cb_before_type_callbacks" : {"ignore" : True},
    "ev_get_idd_opinfo" : {"ignore" : True},
    "ev_loader_elf_machine" : {"ignore" : True},
    "ev_get_regfinder" : {"ignore" : True},
    "ev_broadcast" : {"ignore" : True},
    "ev_obsolete1" : {"ignore" : True},
    "ev_obsolete2" : {"ignore" : True},
    "ev_ana_insn" : {
        "return" : {
            "type" : "bool",
            "default" : "false",
            "convertor" : "IDP_Hooks::bool_to_insn_t_size",
            "convertor_pass_args" : True,
        }
    },
    "ev_out_insn" : {
        "return" : {
            "type" : "bool",
            "default" : "false",
            "convertor" : "IDP_Hooks::bool_to_1or0",
        }
    },
    "ev_emu_insn" : {
        "return" : {
            "type" : "bool",
            "default" : "false",
            "convertor" : "IDP_Hooks::bool_to_1or0",
        }
    },
    "ev_out_operand" : {
        "return" : {
            "type" : "bool",
            "default" : "false",
            "convertor" : "IDP_Hooks::bool_to_1or0",
        }
    },
    "ev_rename" : {
        "params" : {
            "flags" : {
                "suppress_for_call" : True,
                "qnotused" : True,
            },
        },
    },
    "ev_assemble" : {
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
    "ev_decorate_name" : {
        "params" : {
            "cc" : {
                "type" : "int",
                "convertor" : "IDP_Hooks::cm_t_to_ssize_t",
            },
            "outbuf" : { "suppress_for_call" : True, },
            "type" : {
                "rename" : "optional_type",
            }
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_decorate_name3_output",
            "convertor_pass_args" : True,
        }
    },
    "ev_get_reg_name" : {
        "params" : {
            "buf"     : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_get_reg_name_output",
            "convertor_pass_args" : True,
        }
    },
    "ev_delay_slot_insn" : {
        "params" : {
            "ea" : {
                "type" : "ea_t",
                "deref" : {"ifNULL" : "BADADDR"},
            },
            "bexec" : {
                "type" : "bool",
                "deref" : {"ifNULL" : "false"},
            },
            "fexec" : {
                "type" : "bool",
                "deref" : {"ifNULL" : "false"},
            },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_delay_slot_insn_output",
            "convertor_pass_args" : True,
        },
    },
    "ev_adjust_argloc" : {
        "params" : {
            "type" : {
                "rename" : "optional_type",
            }
        },
    },
    "ev_use_regarg_type" : {
        "params" : {
            "idx" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_use_regarg_type_output",
            "convertor_pass_args" : True,
        },
    },
    "ev_demangle_name" : {
        "params" : {
            "out" : { "suppress_for_call" : True, },
            "res" : { "suppress_for_call" : True, },
            "demreq" : { "cast_needed" : "int", "type" : "int" },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_demangle_name_output",
            "convertor_pass_args" : True,
        },
    },
    "ev_find_reg_value" : {
        "params" : {
            "out" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_find_value_output",
            "convertor_pass_args" : True,
        }
    },
    "ev_find_op_value" : {
        "params" : {
            "out" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_find_value_output",
            "convertor_pass_args" : True,
        }
    },
    "ev_get_autocmt" : {
        "params" : {
            "buf" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_get_autocmt_output",
            "convertor_pass_args" : True,
        }
    },
    "ev_get_operand_string" : {
        "params" : {
            "buf" : { "suppress_for_call" : True, },
        },
        "return" : {
            "type" : "PyObject *",
            "retexpr" : "Py_RETURN_NONE",
            "convertor" : "IDP_Hooks::handle_get_operand_string_output",
            "convertor_pass_args" : True,
        }
    },
    "ev_set_idp_options" : {
        "params" : {
            "errbuf" : { "suppress_for_call" : True, "qnotused" : True },
        },
    },
}

default_rtype = "int"
