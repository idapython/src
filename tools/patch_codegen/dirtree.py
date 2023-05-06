{
    "SwigDirector_dirspec_t::get_name" : [
        ("repl_text", (
            "int swig_res = SWIG_AsVal_bool(result, &swig_val);",
            ("int swig_res = PyUnicode_Check(result) && (out == nullptr || PyUnicode_as_qstring(out, result));",
             "  swig_val = static_cast<bool>(swig_res);"))),
        ("director_method_call_arity_cap", (
            True, # add GIL lock
            "get_name",
            "(method ,(PyObject *)obj0,(__argcnt < 2 ? nullptr : (PyObject *)obj1), nullptr)",
            "(swig_get_self(), (PyObject *) swig_method_name ,(PyObject *)obj0,(__argcnt < 3 ? nullptr : (PyObject *)obj1), nullptr)",
        )),
        ("spontaneous_callback_call", (
            False,                               # add GIL lock
            None,                                # try anchor
            None,                                # catch anchor
        )),
    ],
    "SwigDirector_dirspec_t::get_inode" : [
        ("spontaneous_callback_call", None)
    ],
    "SwigDirector_dirspec_t::get_attrs" : [
        ("spontaneous_callback_call", None)
    ],
    "SwigDirector_dirspec_t::rename_inode" : [
        ("spontaneous_callback_call", None)
    ],
    "SwigDirector_dirspec_t::unlink_inode" : [
        ("spontaneous_callback_call", (
            True,                                # add GIL lock
            "  swig::SwigVar_PyObject obj0;",    # try anchor
            "}"                                  # catch anchor
        ))
    ],
}

