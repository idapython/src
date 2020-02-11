%{
#include <enum.hpp>
%}
%ignore get_enum_name(tid_t, int);

%constant bmask_t DEFMASK = bmask_t(-1);

%include "enum.hpp"
