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
