// TODO: This could be wrapped.
%ignore QueueGet;

// Kernel-only & unexported symbols
%ignore QueueDel;
%ignore init_queue;
%ignore save_queue;
%ignore term_queue;
%ignore move_problems;
%ignore queue_del;

%ignore mark_rollback;
%ignore get_rollback_type;
%ignore mark_ida_decision;
%ignore unmark_ida_decision;

%include "queue.hpp"