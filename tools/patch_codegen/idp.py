{
    "SwigDirector_IDP_Hooks::ev_get_bg_color" : [

        ("director_method_call_arity_cap", (
            "ev_get_bg_color",
            "(method , __argcnt == 2 ? (PyObject *) obj1 : (PyObject *) obj0, __argcnt == 2 ? (PyObject *) NULL : (PyObject *) obj1, NULL)",
            "(swig_get_self(), (PyObject *) swig_method_name , __argcnt == 2 ? (PyObject *) obj1 : (PyObject *) obj0, __argcnt == 2 ? (PyObject *) NULL : (PyObject *) obj1, NULL)")
        ),

        ("insert_before_text", ("int swig_val;",
"""
if ( __argcnt == 2 )
{
  if ( result == Py_None )
  {
    result = IDAPyInt_FromLong(0);
  }
  else if ( IDAPyInt_Check(result) )
  {
    *color = bgcolor_t(IDAPyInt_AsLong(result));
    result = IDAPyInt_FromLong(1);
  }
}
""")),

    ],
}
