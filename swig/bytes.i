%{
#include <bytes.hpp>
%}

%apply (testf_t *func, void *ud) { (testf_t *testf, void *ud=nullptr) };

// Unexported and kernel-only declarations
%ignore adjust_visea;
%ignore visit_patched_bytes;
%ignore is_first_visea;
%ignore is_last_visea;
%ignore is_visible_finally;
%ignore setFlbits;
%ignore clrFlbits;
%ignore del_opinfo;
%ignore del_one_opinfo;
%ignore coagulate;

%ignore FlagsInit;
%ignore FlagsTerm;
%ignore FlagsReset;
%ignore get_flags_linput;
%ignore data_type_t::data_type_t();
%ignore data_type_t::cbsize;
%ignore data_type_t::ud;
%ignore data_type_t::may_create_at;
%ignore data_type_t::calc_item_size;
%ignore data_format_t::data_format_t();
%ignore data_format_t::cbsize;
%ignore data_format_t::ud;
%ignore data_format_t::print;
%ignore data_format_t::scan;
%ignore data_format_t::analyze;

%ignore get_bytes;
%ignore get_strlit_contents;
%ignore get_hex_string;
%ignore bin_search; // we redefine our own, w/ 2 params swapped, so we can apply the typemaps below
%rename (bin_search) py_bin_search;
%rename (bin_search) bin_search2;
%rename (op_stroff) py_op_stroff;
%ignore bin_search2(ea_t, ea_t, const uchar *, const uchar *, size_t, int);
%ignore bytes_match_for_bin_search;

%ignore get_8bit;
%rename (get_8bit) py_get_8bit;

%ignore get_octet;
%rename (get_octet) py_get_octet;

%apply uchar * OUTPUT { uchar *out }; // get_octet2

%template(compiled_binpat_vec_t) qvector<compiled_binpat_t>;

%apply size_t * OUTPUT { size_t *out_matched_idx }; // bin_search3

// TODO: This could be fixed (if needed)
%ignore set_dbgmem_source;

%typemap(argout) opinfo_t *buf {
  if ( result != nullptr )
  {
    // kludge: discard newly-constructed object; return input
    Py_XDECREF($result);
    $result = $input;
    Py_INCREF($result);
  }
}

%ignore unregister_custom_data_format;
%rename (unregister_custom_data_format) py_unregister_custom_data_format;
%ignore register_custom_data_format;
%rename (register_custom_data_format) py_register_custom_data_format;
%ignore unregister_custom_data_type;
%rename (unregister_custom_data_type) py_unregister_custom_data_type;
%ignore register_custom_data_type;
%rename (register_custom_data_type) py_register_custom_data_type;
%ignore print_strlit_type;
%rename (print_strlit_type) py_print_strlit_type;

%{
//<code(py_bytes)>
//</code(py_bytes)>
%}

%{
//<code(py_bytes_custdata)>
//</code(py_bytes_custdata)>
%}

%extend data_type_t
{
  data_type_t(
          PyObject *self,
          const char *name,
          asize_t value_size=0,
          const char *menu_name=nullptr,
          const char *hotkey=nullptr,
          const char *asm_keyword=nullptr,
          int props=0)
  {
    py_custom_data_type_t *inst = new py_custom_data_type_t(
            self,
            name,
            value_size,
            menu_name,
            hotkey,
            asm_keyword,
            props);
    return inst;
  }

  ~data_type_t()
  {
    delete (py_custom_data_type_t *) $self;
  }

  int __get_id() { return py_custom_data_type_t_get_id($self); }

  %pythoncode
  {
    id = property(__get_id)
    __real__init__ = __init__
    def __init__(self, *args):
        self.__real__init__(self, *args) # pass 'self' as part of args
  }
}

%extend data_format_t
{
  data_format_t(
          PyObject *self,
          const char *name,
          asize_t value_size=0,
          const char *menu_name=nullptr,
          int props=0,
          const char *hotkey=nullptr,
          int32 text_width=0)
  {
    py_custom_data_format_t *inst = new py_custom_data_format_t(
            self,
            name,
            value_size,
            menu_name,
            props,
            hotkey,
            text_width);
    return inst;
  }

  ~data_format_t()
  {
    delete (py_custom_data_format_t *) $self;
  }

  int __get_id() { return py_custom_data_format_t_get_id($self); }

  %pythoncode
  {
    id = property(__get_id)
    __real__init__ = __init__
    def __init__(self, *args):
        self.__real__init__(self, *args) # pass 'self' as part of args
  }
}

//<typemaps(bytes)>
//</typemaps(bytes)>

%include "bytes.hpp"

// Make it so that 'imask' can be None
%apply (const bytevec_t &_fields) { const bytevec_t &imask };
%typemap(typecheck, precedence=SWIG_TYPECHECK_STRING_ARRAY) const bytevec_t &imask
{ // %typemap(typecheck, precedence=SWIG_TYPECHECK_STRING_ARRAY) const bytevec_t &imask
  $1 = ($input == Py_None || PyBytes_Check($input)) ? 1 : 0;
}

//
%clear(void *buf, ssize_t size);

%clear(const void *buf, size_t size);
%clear(void *buf, ssize_t size);
%clear(opinfo_t *);

%rename (visit_patched_bytes) py_visit_patched_bytes;
%rename (get_bytes) py_get_bytes;
%rename (get_bytes_and_mask) py_get_bytes_and_mask;
%rename (get_strlit_contents) py_get_strlit_contents;

%inline %{
//<inline(py_bytes)>
//</inline(py_bytes)>
%}

%pythoncode %{
#<pycode(py_bytes)>
#</pycode(py_bytes)>
%}

%inline %{
//<inline(py_bytes_custdata)>
//</inline(py_bytes_custdata)>
%}

%pythoncode %{
#<pycode(py_bytes_custdata)>
#</pycode(py_bytes_custdata)>
%}
