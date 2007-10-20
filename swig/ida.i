// Ignore kernel-only symbols
%ignore dual_text_options_t;
%ignore init;
%ignore retrieve;
%ignore read;
%ignore write;

// Make idainfo::get_proc_name() work
%cstring_bounded_output(char *buf, 8);

%include "ida.hpp"

%clear(char *buf);
