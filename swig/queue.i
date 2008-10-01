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
%ignore had_rolled_back;

%include "queue.hpp"