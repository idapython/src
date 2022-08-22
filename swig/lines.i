// FIXME: These should be fixed
%ignore requires_color_esc;
// Ignore va_list versions
%ignore vadd_extra_line;
// Kernel-only and unexported symbols
%ignore get_last_pfxlen;
%ignore closing_comment;
%ignore close_comment;
%ignore init_lines;
%ignore save_lines;
%ignore align_down_to_stack;
%ignore align_up_to_stack;
%ignore encoder_t;
%ignore file_producer_t;

%typemap(default) const void *owner {
  $1 = nullptr;
}

// compat
%ignore set_user_defined_prefix;
%rename (set_user_defined_prefix) py_set_user_defined_prefix;
// end compat

%ignore generate_disassembly;
%rename (generate_disassembly) py_generate_disassembly;

%ignore tag_remove;
%rename (tag_remove) py_tag_remove;

%ignore tag_addr;
%rename (tag_addr) py_tag_addr;

%ignore tag_skipcodes;
%rename (tag_skipcodes) py_tag_skipcodes;

%ignore tag_skipcode;
%rename (tag_skipcode) py_tag_skipcode;

%ignore tag_advance;
%rename (tag_advance) py_tag_advance;

%typemap(argout) (qstring *buf, ea_t ea, int what)
{
  // typemap(argout) (qstring *buf, ea_t ea, int what)
  Py_XDECREF(resultobj);
  if (result >= 0)
  {
    resultobj = PyUnicode_FromStringAndSize((const char *) $1->c_str(), $1->length());
  }
  else
  {
    Py_INCREF(Py_None);
    resultobj = Py_None;
  }
}

//<typemaps(lines)>
//</typemaps(lines)>

%include "lines.hpp"

%{
//<code(py_lines)>
//</code(py_lines)>
%}

%pywraps_nonnul_argument_prototype(
        PyObject *py_tag_remove(const char *nonnul_instr),
        const char *nonnul_instr);

%inline %{
//<inline(py_lines)>
//</inline(py_lines)>
%}

%pythoncode %{
#<pycode(py_lines)>
#</pycode(py_lines)>
%}
