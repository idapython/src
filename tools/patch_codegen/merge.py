{
    "SwigDirector_merge_node_helper_t::print_entry_name" : [
        ("spontaneous_callback_call", None)
    ],
    "SwigDirector_merge_node_helper_t::print_entry_details" : [
        ("spontaneous_callback_call", (
            True,                              # add GIL lock
            "  swig::SwigVar_PyObject obj0;",  # try anchor
            "}"                                # catch anchor
        )),
    ],
    "SwigDirector_merge_node_helper_t::get_column_headers" : [
        ("spontaneous_callback_call", (
            True,                              # add GIL lock
            "  swig::SwigVar_PyObject obj0;",  # try anchor
            "}"                                # catch anchor
        )),
    ],
    "SwigDirector_merge_node_helper_t::is_mergeable" : [
        ("spontaneous_callback_call", None)
    ],
    "SwigDirector_merge_node_helper_t::get_netnode" : [
        ("spontaneous_callback_call", (
            True,                              # add GIL lock
            "  netnode c_result;",             # try anchor
            None                               # catch anchor
        )),
    ],
    "SwigDirector_merge_node_helper_t::map_scalar" : [
        ("spontaneous_callback_call", (
            True,                              # add GIL lock
            "  swig::SwigVar_PyObject obj0;",  # try anchor
            "}"                                # catch anchor
        )),
    ],
    "SwigDirector_merge_node_helper_t::map_string" : [
        ("spontaneous_callback_call", (
            True,                              # add GIL lock
            "  swig::SwigVar_PyObject obj0;",  # try anchor
            "}"                                # catch anchor
        )),
    ],
    # ignored, see merge.i
    # "SwigDirector_merge_node_helper_t::map_value" : 
    "SwigDirector_merge_node_helper_t::refresh" : [
        ("spontaneous_callback_call", (
            True,                              # add GIL lock
            "  swig::SwigVar_PyObject obj0;",  # try anchor
            "}"                                # catch anchor
        )),
    ],
    # ignored, see merge.i
    # "SwigDirector_merge_node_helper_t::get_log_name" : 
}
