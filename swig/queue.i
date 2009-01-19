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
%ignore mark_ida_decision;
%ignore unmark_ida_decision;

%ignore had_rolled_back;
%ignore ever_rolled_back;

%include "queue.hpp"