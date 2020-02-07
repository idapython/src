%module(docstring="IDA Plugin SDK API wrapper: offset",directors="1",threads="1") ida_offset
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_OFFSET
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_OFFSET
  #define HAS_DEP_ON_INTERFACE_OFFSET
#endif
%include "header.i"
%{
#include <offset.hpp>
%}
%include "offset.hpp"
%pythoncode %{
if _BC695:
    calc_reference_basevalue=calc_basevalue
    calc_reference_target=calc_target
    def set_offset(ea, n, base):
        import ida_idaapi
        otype = get_default_reftype(ea)
        return op_offset(ea, n, otype, ida_idaapi.BADADDR, base) > 0

%}