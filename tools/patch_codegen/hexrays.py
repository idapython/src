{
    "SwigDirector_Hexrays_Hooks::SwigDirector_Hexrays_Hooks" : [
        ("maybe_collect_director_fixed_method_set", None),
    ],

    "SwigDirector_microcode_filter_t::match" : [
        ("spontaneous_callback_call", None)
    ],
    "SwigDirector_microcode_filter_t::apply" : [
        ("spontaneous_callback_call", None)
    ],
    "SwigDirector_udc_filter_t::match" : [
        ("spontaneous_callback_call", None)
    ],
    "SwigDirector_optinsn_t::func" : [
        ("director_method_call_arity_cap", (
            True,  # add GIL lock
            "func",
            "(method ,(PyObject *)obj0,(PyObject *)obj1,(__argcnt < 3 ? NULL : (PyObject *)obj2), NULL)",
            "(swig_get_self(), (PyObject *) swig_method_name ,(PyObject *)obj0,(PyObject *)obj1,(__argcnt < 4 ? NULL : (PyObject *)obj2), NULL)",
        )),
        ("spontaneous_callback_call", (
            False, # add GIL lock
            None,  # try anchor
            None   # catch anchor
        )),
    ],
    "SwigDirector_optblock_t::func" : [
        ("spontaneous_callback_call", None)
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
