
%{
#include <libfuncs.hpp>
%}
%ignore fix_version;
%apply qstring *result { qstring *out_libname};
%apply qstring *result { qstring *out_fullpath};
%include "libfuncs.hpp"