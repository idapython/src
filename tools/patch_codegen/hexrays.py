{
    "SwigDirector_Hexrays_Hooks::SwigDirector_Hexrays_Hooks" : [
        ("maybe_collect_director_fixed_method_set", None),
    ],

    "vcreate_helper" : [
        ("va_copy", ("arg4", "temp")),
    ],
    "vcall_helper" : [
        ("va_copy", ("arg4", "temp")),
    ],
    "Hexrays_Callback" : [
        ("va_copy", ("arg3", "temp")),
    ],
    "SwigDirector_microcode_filter_t::match" : [
        ("spontaneous_callback_call", True)
    ],
    "SwigDirector_microcode_filter_t::apply" : [
        ("spontaneous_callback_call", True)
    ],
    "SwigDirector_udc_filter_t::match" : [
        ("spontaneous_callback_call", True)
    ],
    "SwigDirector_optinsn_t::func" : [
        ("spontaneous_callback_call", True)
    ],
    "SwigDirector_optblock_t::func" : [
        ("spontaneous_callback_call", True)
    ],
    "new_mba_ranges_t" : [
        ("repl_text", (
            "PyObject *argv[2];",
            "PyObject *argv[2] = {0, 0};")),
    ],
    "get_temp_regs" : [
        ("repl_text", (
            "PyObject *argv[2];",
            "PyObject *argv[2] = {0, 0}; qnotused(argv);")),
    ],
    "new_valrng_t" : [
        ("repl_text", (
            "PyObject *argv[2];",
            "PyObject *argv[2] = {0, 0};")),
    ],
}
