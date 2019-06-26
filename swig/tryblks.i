%{
#include <tryblks.hpp>
%}

%ignore tryblk_t::reserve;
%ignore tryblk_t::cpp() const;
%ignore tryblk_t::seh() const;

%template(tryblks_t) qvector<tryblk_t>;
%template(catchvec_t) qvector<catch_t>;

%include "tryblks.hpp"
