%module(docstring="IDA Plugin SDK API wrapper: auto",directors="1",threads="1") ida_auto
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_AUTO
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_AUTO
  #define HAS_DEP_ON_INTERFACE_AUTO
#endif
%include "header.i"
%{
#include <auto.hpp>
%}

%include "auto.hpp"

%pythoncode %{
if _BC695:
    analyze_area = plan_and_wait
    autoCancel = auto_cancel
    autoIsOk = auto_is_ok
    autoMark = auto_mark
    autoUnmark = auto_unmark
    autoWait = auto_wait
    noUsed = plan_ea
    setStat = set_ida_state
    showAddr = show_addr
    showAuto = show_auto

%}