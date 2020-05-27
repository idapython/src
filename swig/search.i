%{
#include <search.hpp>
%}
%apply int * OUTPUT { int *opnum };

%ignore search;
%ignore user2bin;

%inline %{
//<inline(py_search)>
//</inline(py_search)>
%}

%include "search.hpp"
%clear int *opnum;
