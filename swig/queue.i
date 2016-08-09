%{
#include <queue.hpp>
%}
// TODO: This could be wrapped.
%ignore QueueGet;

// Kernel-only & unexported symbols
%ignore QueueDel(ea_t);

%ignore mark_ida_decision;
%ignore unmark_ida_decision;

%include "queue.hpp"
