%module(docstring="IDA Plugin SDK API wrapper: fixup",directors="1",threads="1") ida_fixup
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_FIXUP
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_FIXUP
  #define HAS_DEP_ON_INTERFACE_FIXUP
#endif
%include "header.i"
%{
#include <fixup.hpp>
%}

%ignore apply_fixup;
%ignore fixup_handler_t;
%ignore register_custom_fixup;
%ignore unregister_custom_fixup;

%cstring_output_qstring_returning_charptr(
        1,
        qstring *buf,
        ea_t source); // fixup_data_t::get_desc

%cstring_output_qstring_returning_charptr(
        1,
        qstring *buf,
        ea_t source,
        const fixup_data_t &fd); // get_fixup_desc

%include "fixup.hpp"
%pythoncode %{
if _BC695:
    FIXUP_CREATED=FIXUPF_CREATED
    FIXUP_EXTDEF=FIXUPF_EXTDEF
    FIXUP_REL=FIXUPF_REL

%}