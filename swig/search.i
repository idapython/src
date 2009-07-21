%apply int * OUTPUT { int *opnum };

%ignore search;
%ignore user2bin;

%include "search.hpp"
%clear int *opnum;
