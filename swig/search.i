%apply int * OUTPUT { int *opnum };

// Do not generate overloaded versions for default arguments
%feature("compactdefaultargs") find_error;
%feature("compactdefaultargs") find_notype;
%feature("compactdefaultargs") find_void;
%feature("compactdefaultargs") find_imm;

// FIXME: search() should be checked and enabled
%ignore search;
%ignore user2bin;

%include "search.hpp"
%clear int *opnum;
