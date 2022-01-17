
%{
#include <dirtree.hpp>
%}

%apply SWIGTYPE *DISOWN { dirspec_t *ds };

%template(direntry_vec_t) qvector<direntry_t>;
%template(dirtree_cursor_vec_t) qvector<dirtree_cursor_t>;

//
// compat
//
%ignore dirtree_get_nodename;
%ignore dirtree_set_nodename;

%extend dirspec_t {
  %pythoncode {
      nodename = id
  }
}

%extend dirtree_t {
  %pythoncode {
      get_nodename = get_id
      set_nodename = set_id
  }
}

%include "dirtree.hpp"
