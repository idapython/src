%{
#include <idd.hpp>
#include <dbg.hpp>
#include <ua.hpp>
#include <err.h>
%}

%ignore debugger_t;
%ignore memory_info_t;
%ignore lowcnd_t;
%ignore lowcnd_vec_t;
%ignore update_bpt_info_t;
%ignore update_bpt_vec_t;
%ignore register_info_t;
%ignore appcall;
%ignore idd_opinfo_t;
%ignore gdecode_t;
%apply unsigned char { op_dtype_t dtype };

%ignore qvector<exception_info_t>::operator==;
%ignore qvector<exception_info_t>::operator!=;
%ignore qvector<exception_info_t>::find;
%ignore qvector<exception_info_t>::has;
%ignore qvector<exception_info_t>::del;
%ignore qvector<exception_info_t>::add_unique;
%template(excvec_t) qvector<exception_info_t>;

%ignore qvector<process_info_t>::operator==;
%ignore qvector<process_info_t>::operator!=;
%ignore qvector<process_info_t>::find;
%ignore qvector<process_info_t>::has;
%ignore qvector<process_info_t>::del;
%ignore qvector<process_info_t>::add_unique;
%template(procinfo_vec_t) qvector<process_info_t>;

%include "idd.hpp"

// SWIG chokes on the original declaration so it is replicated here
typedef struct
{
    ulonglong ival;     // 8:  integer value
    ushort    fval[6];  // 12: floating point value in the internal representation (see ieee.h)
} regval_t;

%clear(op_dtype_t dtype);

%rename (appcall) py_appcall;

%{
//<code(py_idd)>
//</code(py_idd)>
%}

%inline %{
//<inline(py_idd)>
//</inline(py_idd)>
%}

%pythoncode %{
#<pycode(py_idd)>
#</pycode(py_idd)>
%}
