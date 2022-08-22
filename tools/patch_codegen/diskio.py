{
    "SwigDirector_ioports_fallback_t::handle" : [
        ("repl_text", (
            "int swig_res = SWIG_AsVal_bool(result, &swig_val);",
            (
                "const bool is_error = PyUnicode_Check(result) != 0;",
                "  int swig_res = is_error || result == Py_None;",
                "  if ( is_error )",
                "    PyUnicode_as_qstring(errbuf, result);",
                "  swig_val = !is_error;",
            ),
        )),
    ],

    "SwigDirector_choose_ioport_parser_t::parse" : [
        ("repl_text", (
            "int swig_res = SWIG_AsVal_bool(result, &swig_val);",
            ("""const bool is_proper_tuple = PyTuple_Check(result) && PyTuple_Size(result) == 2;
  const bool is_item0_bool = is_proper_tuple && PyBool_Check(PyTuple_GetItem(result, 0));
  const bool is_success = is_proper_tuple && is_item0_bool && PyTuple_GetItem(result, 0) == Py_True;
  const bool is_item1_str = is_proper_tuple && PyUnicode_Check(PyTuple_GetItem(result, 1));
  const bool well_formed = is_proper_tuple && is_item0_bool && ((is_success && is_item1_str) || !is_success);
  int swig_res = well_formed;
  if ( well_formed )
  {
    if ( is_item1_str )
      PyUnicode_as_qstring(param, PyTuple_GetItem(result, 1));
    else
      param->qclear();
  }
  swig_val = well_formed ? is_success : false;
""")))
            ],
}
