// Convert this for ver 4.8 tag_remove()
%cstring_output_maxstr_none(char *buf, int bufsize);

// FIXME: These should be fixed
%ignore tag_on;
%ignore tag_off;
%ignore tag_addchr;
%ignore tag_addstr;
%ignore tag_addr;
%ignore tag_advance;
%ignore tag_skipcodes;
%ignore tag_skipcode;
%ignore set_user_defined_prefix;
%ignore get_user_defined_prefix;
// Ignore va_list versions
%ignore printf_line_v;
%ignore gen_colored_cmt_line_v;
%ignore gen_cmt_line_v;
%ignore add_long_cmt_v;
%ignore describex;
// Kernel-only and unexported symbols
%ignore init_sourcefiles;
%ignore save_sourcefiles;
%ignore term_sourcefiles;
%ignore move_sourcefiles;
%ignore gen_xref_lines;
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
%ignore generate_disassembly;
%ignore gen_labeled_line;
%ignore gen_lname_line;
%ignore makeline_producer_t;
%ignore set_makeline_producer;
%ignore closing_comment;
%ignore close_comment;
%ignore copy_extra_lines;
%ignore ExtraLines;
%ignore ExtraKill;
%ignore ExtraFree;
%ignore Dumper;
%ignore init_lines;
%ignore save_lines;
%ignore term_lines;
%ignore gl_namedone;
%ignore data_as_stack;
%ignore calc_stack_alignment;
%ignore align_down_to_stack;
%ignore align_up_to_stack;
%ignore remove_spaces;

%include "lines.hpp"

%clear(char *buf, int bufsize);
