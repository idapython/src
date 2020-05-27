
recipe = {
    "synthetic_params" : {
        "@pid" : {
            "type" : "pid_t",
            "synth" : "event->pid",
        },
        "@tid" : {
            "type" : "thid_t",
            "synth" : "event->tid",
        },
        "@ea" : {
            "type" : "ea_t",
            "synth" : "event->ea",
        },
        "@modinfo_name" : {
            "type" : "const char *",
            "synth" : "event->modinfo().name.c_str()",
        },
        "@modinfo_base" : {
            "type" : "ea_t",
            "synth" : "event->modinfo().base",
        },
        "@modinfo_size" : {
            "type" : "asize_t",
            "synth" : "event->modinfo().size",
        },
        "@exit_code" : {
            "type" : "int",
            "synth" : "event->exit_code()",
        },
        "@info" : {
            "type" : "const char *",
            "synth" : "event->info().c_str()",
        },

        "@exc_code" : {
            "type" : "int",
            "synth" : "event->exc().code",
        },
        "@exc_can_cont" : {
            "type" : "bool",
            "synth" : "event->exc().can_cont",
        },
        "@exc_ea" : {
            "type" : "ea_t",
            "synth" : "event->exc().ea",
        },
        "@exc_info" : {
            "type" : "const char *",
            "synth" : "event->exc().info.c_str()",
        },
    },

    "dbg_null" : {
        "ignore" : True
    },
    "dbg_last" : {
        "ignore" : True
    },
    "dbg_process_start" : {
        "call_params" : ["@pid", "@tid", "@ea", "@modinfo_name", "@modinfo_base", "@modinfo_size"],
    },
    "dbg_process_exit" : {
        "call_params" : ["@pid", "@tid", "@ea", "@exit_code"],
    },
    "dbg_process_attach" : {
        "call_params" : ["@pid", "@tid", "@ea", "@modinfo_name", "@modinfo_base", "@modinfo_size"],
    },
    "dbg_process_detach" : {
        "call_params" : ["@pid", "@tid", "@ea"],
    },
    "dbg_thread_start" : {
        "call_params" : ["@pid", "@tid", "@ea"],
    },
    "dbg_thread_exit" : {
        "call_params" : ["@pid", "@tid", "@ea", "@exit_code"],
    },
    "dbg_library_load" : {
        "call_params" : ["@pid", "@tid", "@ea", "@modinfo_name", "@modinfo_base", "@modinfo_size"],
    },
    "dbg_library_unload" : {
        "call_params" : ["@pid", "@tid", "@ea", "@info"],
    },
    "dbg_information" : {
        "call_params" : ["@pid", "@tid", "@ea", "@info"],
    },
    "dbg_exception" : {
        "call_params" : ["@pid", "@tid", "@ea", "@exc_code", "@exc_can_cont", "@exc_ea", "@exc_info"],
        "return" : {
            "type" : "int",
            "default" : "0",
            "convertor" : "DBG_Hooks::store_int",
            "convertor_pass_args" : True,
            "convertor_pass_args_nosynth" : True,
        }
    },
    "dbg_suspend_process" : {
        "params" : {
            "event" : {
                "suppress_for_call" : True,
                "qnotused" : True,
            },
        },
    },
    "dbg_bpt" : {
        "params" : {
            "warn" : {
                "suppress_for_call" : True,
            },
        },
        "return" : {
            "type" : "int",
            "default" : "0",
            "convertor" : "DBG_Hooks::store_int",
            "convertor_pass_args" : True,
        }
    },
    "dbg_trace" : {
        "return" : {
            "type" : "int",
            "default" : "0",
        }
    },
    "dbg_request_error" : {
        "params" : {
            "failed_command" : {
                "type" : "int",
                "cast_needed" : "int",
            },
            "failed_dbg_notification" : {
                "type" : "int",
                "cast_needed" : "int",
            },
        }
    },
    "dbg_step_into" : {
        "params" : {
            "event" : {
                "suppress_for_call" : True,
                "qnotused" : True,
            },
        },
    },
    "dbg_step_over" : {
        "params" : {
            "event" : {
                "suppress_for_call" : True,
                "qnotused" : True,
            },
        },
    },
    "dbg_run_to" : {
        "call_params" : ["@pid", "@tid", "@ea"],
    },
    "dbg_step_until_ret" : {
        "params" : {
            "event" : {
                "suppress_for_call" : True,
                "qnotused" : True,
            },
        },
    },
}

default_rtype = "void"
