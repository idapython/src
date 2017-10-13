%{
#include <enum.hpp>
%}
%ignore get_enum_name(tid_t);

%constant bmask_t DEFMASK = bmask_t(-1);

%include "enum.hpp"
