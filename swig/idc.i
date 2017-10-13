
// This contains helpers needed for idc.py to work correctly

%{
#include <pro.h>
#include <moves.hpp>
%}

%{
//<code(py_idc)>
//</code(py_idc)>
%}

%inline %{
//<inline(py_idc)>
//</inline(py_idc)>
%}

%pythoncode %{
#<pycode(py_idc)>
#</pycode(py_idc)>
%}
