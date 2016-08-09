%{
#include <fixup.hpp>
%}

%ignore apply_fixup;
%ignore custom_fixup_handler_t;
%ignore custom_fixup_handlers_t;
%ignore register_custom_fixup;
%ignore unregister_custom_fixup;
%ignore set_custom_fixup;

%include "fixup.hpp"

