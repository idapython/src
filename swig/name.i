%cstring_output_maxstr_none(char *buf, int bufsize);

%cstring_bounded_output(char *dstname, MAXSTR);
%cstring_bounded_output(char *buf, MAXSTR);

// This is for get_name_value's output value
%apply unsigned long *OUTPUT { uval_t *value };

// FIXME: These should be fixed
%ignore append_struct_fields;
%ignore get_struct_operand;
%ignore set_debug_names;
%ignore get_debug_name;
%ignore nameVa;

// Unexported & kernel-only
%ignore get_short_name;
%ignore get_long_name;
%ignore get_colored_short_name;
%ignore get_colored_long_name;
%ignore addDummyName;
%ignore convert_debug_names_to_normal;
%ignore convert_name_formats;
%ignore showhide_name;
%ignore clear_lname_bit;
%ignore fix_new_name;
%ignore rename;
%ignore move_names;
%ignore is_noret_name;
%ignore is_exit_name;
%ignore dummy_name_ea;

%include "name.hpp"

