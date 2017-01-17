%{
#include <bytes.hpp>
%}

%import "area.i"

// Unexported and kernel-only declarations
%ignore FlagsEnable;
%ignore FlagsDisable;
%ignore testf_t;
%ignore nextthat;
%ignore prevthat;
%ignore adjust_visea;
%ignore prev_visea;
%ignore next_visea;
%ignore visit_patched_bytes;
%ignore is_first_visea;
%ignore is_last_visea;
%ignore is_visible_finally;
%ignore fluFlags;
%ignore setFlbits;
%ignore clrFlbits;
%ignore get_8bit;
%ignore get_ascii_char;
%ignore del_opinfo;
%ignore del_one_opinfo;
%ignore doCode;
%ignore get_repeatable_cmt;
%ignore get_any_indented_cmt;
%ignore del_code_comments;
%ignore doFlow;
%ignore noFlow;
%ignore coagulate;

%ignore FlagsInit;
%ignore FlagsTerm;
%ignore FlagsReset;
%ignore flush_flags;
%ignore get_flags_linput;
%ignore data_type_t;
%ignore data_format_t;
%ignore get_custom_data_type;
%ignore get_custom_data_format;
%ignore unregister_custom_data_format;
%ignore register_custom_data_format;
%ignore unregister_custom_data_type;
%ignore register_custom_data_type;
%ignore get_many_bytes;
%ignore get_many_bytes_ex;
%ignore get_ascii_contents;
%ignore get_ascii_contents2;
%ignore get_hex_string;

// TODO: This could be fixed (if needed)
%ignore set_dbgmem_source;

%typemap(argout) opinfo_t *buf {
  if ( result != NULL )
  {
    // kludge: discard newly-constructed object; return input
    Py_XDECREF($result);
    $result = $input;
    Py_INCREF($result);
  }
}

%include "bytes.hpp"

%clear(void *buf, ssize_t size);

%clear(const void *buf, size_t size);
%clear(void *buf, ssize_t size);
%clear(opinfo_t *);

%rename (visit_patched_bytes) py_visit_patched_bytes;
%rename (nextthat) py_nextthat;
%rename (prevthat) py_prevthat;
%rename (get_custom_data_type) py_get_custom_data_type;
%rename (get_custom_data_format) py_get_custom_data_format;
%rename (unregister_custom_data_format) py_unregister_custom_data_format;
%rename (register_custom_data_format) py_register_custom_data_format;
%rename (unregister_custom_data_type) py_unregister_custom_data_type;
%rename (register_custom_data_type) py_register_custom_data_type;
%rename (get_many_bytes) py_get_many_bytes;
%rename (get_many_bytes_ex) py_get_many_bytes_ex;
%rename (get_ascii_contents) py_get_ascii_contents;
%rename (get_ascii_contents2) py_get_ascii_contents2;
%{
//<code(py_bytes)>
//</code(py_bytes)>
%}

%inline %{
//<inline(py_bytes)>
//</inline(py_bytes)>
%}

%pythoncode %{
#<pycode(py_bytes)>
#</pycode(py_bytes)>
%}

%{
//<code(py_bytes_custdata)>
//</code(py_bytes_custdata)>
%}

%inline %{
//<inline(py_bytes_custdata)>
//</inline(py_bytes_custdata)>
%}

%pythoncode %{
#<pycode(py_bytes_custdata)>
#</pycode(py_bytes_custdata)>
%}
