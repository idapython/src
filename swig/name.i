
%{
#include <demangle.hpp>
%}

%include "cstring.i"
%cstring_bounded_output(char *dstname, MAXSTR);
%cstring_bounded_output(char *buf, MAXSTR);

%typemap(check) uval_t *value { *($1) = BADADDR; } // get_name_value

// FIXME: These should be fixed
%ignore get_struct_operand;
%ignore set_debug_names;

// Unexported & kernel-only
%ignore is_exit_name;
%ignore dummy_name_ea;
%ignore calc_gtn_flags;
%ignore detect_compiler_using_demangler;
%ignore getname_info_t;
%ignore get_ea_name;
%rename (get_ea_name) py_get_ea_name;

// Duplicate names, in-out qstring w/ existing
// qstring-returning alternatives.
%ignore get_visible_name(qstring *, ea_t, int);
%ignore get_short_name(qstring *, ea_t, int);
%ignore get_long_name(qstring *, ea_t, int);
%ignore get_colored_short_name(qstring *, ea_t, int);
%ignore get_colored_long_name(qstring *, ea_t, int);
%ignore get_demangled_name(qstring *, ea_t, int32, int, int);
%ignore get_colored_demangled_name(qstring *, ea_t, int32, int, int);

%uncomparable_elements_qvector(ea_name_t, ea_name_vec_t);

// get_name & get_colored_name have prototypes such that,
// once converted to IDAPython, would be problematic because it'd
// be impossible for SWiG to tell apart the (ea_t, ea_t) version
// from the (ea_t, int) one.
// Therefore, we cannot allow access to the (ea_t, int) one (and
// we keep the other for bw-compat reasons). If users want to use
// 'flags' versions, they can still rely on get_ea_name().
%define %restrict_ambiguous_name_function(FNAME)
%ignore FNAME(qstring *, ea_t, int);
%ignore FNAME(ea_t, int);
%rename (FNAME) py_ ## FNAME;

%ignore demangle_name(const char *, uint32, demreq_type_t);

%inline %{
inline qstring py_## FNAME(ea_t ea) { return FNAME(ea); }
%}
%enddef

%restrict_ambiguous_name_function(get_name);
%restrict_ambiguous_name_function(get_colored_name);

%ignore validate_name;
%rename (validate_name) py_validate_name;

%{
//<code(py_name)>
//</code(py_name)>
%}

%include "name.hpp"

%ignore demangle;
%include "demangle.hpp"

%inline %{
//<inline(py_name)>
//</inline(py_name)>
%}

%pythoncode %{
#<pycode(py_name)>
#</pycode(py_name)>
%}

