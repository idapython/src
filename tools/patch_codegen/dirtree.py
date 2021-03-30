{
    "SwigDirector_dirspec_t::get_name" : [
        ("spontaneous_callback_call", None),
        ("repl_text", (
            "int swig_res = SWIG_AsVal_bool(result, &swig_val);",
            ("int swig_res = IDAPyStr_Check(result) && (out == nullptr || IDAPyStr_AsUTF8(out, result));",
             "  swig_val = static_cast<bool>(swig_res);"))),
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

