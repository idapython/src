%module(docstring="IDA Plugin SDK API wrapper: entry",directors="1",threads="1") ida_entry
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_ENTRY
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_ENTRY
  #define HAS_DEP_ON_INTERFACE_ENTRY
#endif
%include "header.i"
%{
#include <entry.hpp>
%}

%include "entry.hpp"
