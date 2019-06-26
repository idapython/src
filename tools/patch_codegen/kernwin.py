{
    "vask_file" : [
        ("va_copy", ("arg4", "temp")),
    ],
    "SwigDirector_UI_Hooks::SwigDirector_UI_Hooks" : [
        ("maybe_collect_director_fixed_method_set", None),
    ],
    "SwigDirector_View_Hooks::SwigDirector_View_Hooks" : [
        ("maybe_collect_director_fixed_method_set", None),
    ],
    "SwigDirector_UI_Hooks::populating_widget_popup" : [
        ("director_method_call_arity_cap", (
            "populating_widget_popup",
            "(method ,(PyObject *)obj0,(PyObject *)obj1,(__argcnt < 3 ? NULL : (PyObject *)obj2), NULL)",
            "(swig_get_self(), (PyObject *) swig_method_name ,(PyObject *)obj0,(PyObject *)obj1,(__argcnt < 4 ? NULL : (PyObject *)obj2), NULL)",
        )),
    ],
    "SwigDirector_UI_Hooks::finish_populating_widget_popup" : [
        ("director_method_call_arity_cap", (
            "finish_populating_widget_popup",
            "(method ,(PyObject *)obj0,(PyObject *)obj1,(__argcnt < 3 ? NULL : (PyObject *)obj2), NULL)",
            "(swig_get_self(), (PyObject *) swig_method_name ,(PyObject *)obj0,(PyObject *)obj1,(__argcnt < 4 ? NULL : (PyObject *)obj2), NULL)",
        )),
    ],
    "__additional_thread_unsafe__" : ["py_get_ask_form", "py_get_open_form"],
    "error__varargs__" : [
        ("repl_text", ("resultobj = SWIG_Py_Void();", " // resultobj = SWIG_Py_Void();")),
        ("repl_text", ("return resultobj;", "qnotused(resultobj); // return resultobj;")),
    ],
    "nomem__varargs__" : [
        ("repl_text", ("resultobj = SWIG_Py_Void();", " // resultobj = SWIG_Py_Void();")),
        ("repl_text", ("return resultobj;", "qnotused(resultobj); // return resultobj;")),
    ],

}
