%{
#include <search.hpp>
%}
%apply int * OUTPUT { int *opnum };

%ignore search;
%ignore user2bin;

%ignore find_error(ea_t,int);
%ignore find_notype(ea_t,int);
%ignore find_suspop(ea_t,int);
%ignore find_imm(ea_t,int,uval_t);

%pythoncode %{
#<pycode(py_search)>
#</pycode(py_search)>
%}

%inline %{
//<inline(py_search)>
//</inline(py_search)>
%}

%include "search.hpp"
%clear int *opnum;
