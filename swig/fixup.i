%{
#include <fixup.hpp>
%}

%ignore apply_fixup;
%ignore custom_fixup_handler_t;
%ignore custom_fixup_handlers_t;
%ignore register_custom_fixup;
%ignore unregister_custom_fixup;
%ignore set_custom_fixup;

%nonnul_argument_prototype(
        idaman void ida_export set_fixup(ea_t source, const fixup_data_t *nonnul_fp),
        const fixup_data_t *nonnul_fp);

%include "fixup.hpp"
