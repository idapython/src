%{
#include <idd.hpp>
#include <dbg.hpp>
#include <ua.hpp>
#include <err.h>
%}

%ignore dynamic_register_set_t;
%ignore serialize_dynamic_register_set;
%ignore deserialize_dynamic_register_set;
%ignore free_debug_event;
%ignore copy_debug_event;
%ignore debugger_t;
%ignore lowcnd_t;
%ignore lowcnd_vec_t;
%ignore update_bpt_info_t;
%ignore update_bpt_vec_t;
%ignore appcall;
%ignore idd_opinfo_t;
%ignore gdecode_t;
%ignore memory_buffer_t;
%ignore debug_event_t::exit_code();
%ignore append_regval;
%ignore extract_regvals;
%ignore unpack_regvals;
%apply unsigned char { op_dtype_t dtype };
%ignore regval_t::_set_int;
%ignore regval_t::_set_float;
%ignore regval_t::_set_bytes;
%ignore regval_t::_set_unavailable;

%uncomparable_elements_qvector(exception_info_t, excvec_t);
%uncomparable_elements_qvector(process_info_t, procinfo_vec_t);
%template(call_stack_info_vec_t) qvector<call_stack_info_t>;
%template(meminfo_vec_template_t) qvector<memory_info_t>;

%include "idd.hpp"

// SWIG chokes on the original declaration so it is replicated here
typedef struct
{
    uint64 ival;     // 8:  integer value
    ushort fval[6];  // 12: floating point value in the internal representation (see ieee.h)
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
