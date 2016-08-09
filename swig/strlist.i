%{
#include <strlist.hpp>
%}

%ignore strwinsetup_t::setup_strings_window;
%ignore strwinsetup_t::save_config;
%ignore strwinsetup_t::restore_config;

%include "strlist.hpp"
