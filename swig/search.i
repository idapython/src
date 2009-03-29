%apply int * OUTPUT { int *opnum };

// FIXME: search() should be checked and enabled
%ignore search;
%ignore user2bin;

%include "search.hpp"
%clear int *opnum;
