%module(docstring="IDA Plugin SDK API wrapper: tryblks",directors="1",threads="1") ida_tryblks
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_TRYBLKS
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_TRYBLKS
  #define HAS_DEP_ON_INTERFACE_TRYBLKS
#endif
#ifndef HAS_DEP_ON_INTERFACE_RANGE
  #define HAS_DEP_ON_INTERFACE_RANGE
#endif
%include "header.i"
%{
#include <tryblks.hpp>
%}

%import "range.i"

%ignore tryblk_t::reserve;
%ignore tryblk_t::cpp() const;
%ignore tryblk_t::seh() const;

%template(tryblks_t) qvector<tryblk_t>;
%template(catchvec_t) qvector<catch_t>;

%include "tryblks.hpp"
