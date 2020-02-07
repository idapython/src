%module(docstring="IDA Plugin SDK API wrapper: search",directors="1",threads="1") ida_search
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_SEARCH
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_SEARCH
  #define HAS_DEP_ON_INTERFACE_SEARCH
#endif
%include "header.i"
%{
#include <search.hpp>
%}
%apply int * OUTPUT { int *opnum };

%ignore search;
%ignore user2bin;

%include "search.hpp"
%clear int *opnum;
%pythoncode %{
if _BC695:
    find_void=find_suspop

%}