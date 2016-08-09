// FIXME: These should be fixed
%ignore requires_color_esc;
%ignore tag_on;
%ignore tag_off;
%ignore tag_addchr;
%ignore tag_addstr;
%ignore get_user_defined_prefix;
// Ignore va_list versions
%ignore printf_line_v;
%ignore gen_colored_cmt_line_v;
%ignore gen_cmt_line_v;
%ignore add_long_cmt_v;
%ignore describex;
// Kernel-only and unexported symbols
%ignore save_sourcefiles;
%ignore ml_getcmt_t;
%ignore ml_getnam_t;
%ignore ml_genxrf_t;
%ignore ml_saver_t;
%ignore setup_makeline;
%ignore MAKELINE_NONE;
%ignore MAKELINE_BINPREF;
%ignore MAKELINE_VOID;
%ignore MAKELINE_STACK;
%ignore save_line_in_array;
%ignore init_lines_array;
%ignore finish_makeline;
%ignore makeline_producer_t;
%ignore closing_comment;
%ignore close_comment;
%ignore init_lines;
%ignore save_lines;
%ignore align_down_to_stack;
%ignore align_up_to_stack;
%ignore bgcolors;

%ignore set_user_defined_prefix;
%rename (set_user_defined_prefix) py_set_user_defined_prefix;

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

%include "lines.hpp"

%{
//<code(py_lines)>
//</code(py_lines)>
%}

%inline %{
//<inline(py_lines)>
//</inline(py_lines)>
%}

%pythoncode %{
#<pycode(py_lines)>
#</pycode(py_lines)>
%}
