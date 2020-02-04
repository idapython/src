%module(docstring="IDA Plugin SDK API wrapper: allins",directors="1",threads="1") ida_allins
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_ALLINS
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_ALLINS
  #define HAS_DEP_ON_INTERFACE_ALLINS
#endif
%include "header.i"
%{
#include <allins.hpp>
%}

// Ignore the unnedded externals
%ignore Instructions;

%include "allins.hpp"
