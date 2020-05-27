
%{
#include <dirtree.hpp>
%}

%apply SWIGTYPE *DISOWN { dirspec_t *ds };

%template(direntry_vec_t) qvector<direntry_t>;
%template(dirtree_cursor_vec_t) qvector<dirtree_cursor_t>;

%include "dirtree.hpp"
