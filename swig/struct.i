// Kernel-only symbols
%ignore init_structs;
%ignore save_structs;
%ignore term_structs;
%ignore get_struc_name(tid_t);
%ignore get_member_name2(tid_t);

%ignore sync_from_struc;

%include "struct.hpp"
// Add a get_member() member function to struc_t.
// This helps to access the members array in the class.
%extend struc_t {
    member_t *get_member(int index) { return &(self->members[index]); }
}

