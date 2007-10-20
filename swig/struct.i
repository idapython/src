// Kernel-only symbols
%ignore init_struc;
%ignore save_struc;
%ignore term_struc;

%feature("compactdefaultargs") add_struc;

%include "struct.hpp"
// Add a get_member() member function to struc_t.
// This helps to access the members array in the class.
%extend struc_t {
	member_t * get_member(int index) { return &(self->members[index]); }
}

