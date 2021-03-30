%ignore ext_idcfunc_t;
%ignore idcfuncs_t;
%ignore extlang_t;
%ignore extlang_object_t;
%ignore extlang_ptr_t;
%ignore extlangs_t;
%ignore extlangs;
%ignore install_extlang;
%ignore remove_extlang;
%ignore select_extlang;
%ignore get_extlang;
%ignore get_current_extlang;
%ignore find_extlang;
%ignore find_extlang_by_ext;
%ignore find_extlang_by_name;
%ignore find_extlang_by_index;
%ignore find_extlang_kind_t;
%ignore for_all_extlangs;
%ignore extlang_visitor_t;
%ignore set_idc_dtor;
%ignore set_idc_method;
%ignore set_idc_getattr;
%ignore set_idc_setattr;
%ignore add_idc_func;
%ignore del_idc_func;
%ignore VarLong;
%ignore VarNum;
%ignore extlang_get_attr_exists;
%ignore extlang_create_object_exists;
%ignore create_script_object;
%ignore set_script_attr;
%ignore set_attr_exists;
%ignore get_script_attr;
%ignore extlang_get_attr_exists;
%ignore extlang_compile_file;
%ignore get_extlangs;
%ignore create_idc_object;
%ignore run_script_func;
%ignore VarFloat;
%ignore VarFree;
%ignore eval_expr_long;
%ignore call_idc_func;
%ignore eval_idc_snippet;
%ignore set_idc_func_body;
%ignore get_idc_func_body;
%ignore idc_vars;
%ignore setup_lowcnd_regfuncs;
%ignore syntax_highlighter_t;
%ignore get_idptype_and_data;
%ignore idc_resolver_t;
%ignore idc_value_t::_set_long;
%ignore idc_value_t::_set_float;
%ignore idc_value_t::_set_int64;
%ignore idc_value_t::_set_pvoid;
%ignore idc_value_t::_set_string;
%ignore idc_value_t::idc_value_t(const qstring &);
%ignore idc_value_t::set_string(const qstring &);

%ignore eval_expr;
%rename (eval_expr) py_eval_expr;
%ignore eval_idc_expr;
%rename (eval_idc_expr) py_eval_idc_expr;
%ignore compile_idc_file;
%rename (compile_idc_file) py_compile_idc_file;
%ignore compile_idc_text;
%rename (compile_idc_text) py_compile_idc_text;

%cstring_output_buf_and_size_returning_charptr(
        1,
        char *buf,
        size_t bufsize,
        const char *file); // get_idc_filename

%pywraps_nonnul_argument_prototype(
        bool py_compile_idc_file(const char *nonnul_line, qstring *errbuf),
        const char *nonnul_line);
%pywraps_nonnul_argument_prototype(
        bool py_compile_idc_text(const char *nonnul_line, qstring *errbuf),
        const char *nonnul_line);
%{
//<code(py_expr)>
//</code(py_expr)>
%}

%inline %{
//<inline(py_expr)>
//</inline(py_expr)>
%}

%include "expr.hpp"

%extend idc_value_t
{
  %pythoncode {
    str = property(lambda self: self.c_str(), lambda self, v: self.set_string(v))
  }
}

%uncomparable_elements_qvector(idc_value_t, idc_values_t);

%pythoncode %{
#<pycode(py_expr)>
#</pycode(py_expr)>
%}
