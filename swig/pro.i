
%include "pro.h"

// we must include those manually here
%import "ida.hpp"
%import "xref.hpp"
%import "typeinf.hpp"
%import "enum.hpp"
%import "netnode.hpp"
//

//---------------------------------------------------------------------
%template(uvalvec_t)  qvector<uval_t>; // unsigned values
%template(intvec_t)   qvector<int>;
%template(int64vec_t) qvector<long long>; // for EA64 svalvec_t objects
%template(boolvec_t)  qvector<bool>;
%template(strvec_t)   qvector<simpleline_t>;

SWIG_DECLARE_PY_CLINKED_OBJECT(qstrvec_t)

%inline %{
//<inline(py_pro)>
//</inline(py_pro)>
%}

%include "carrays.i"
%include "cpointer.i"
%array_class(uchar, uchar_array);
%array_class(tid_t, tid_array);
%array_class(ea_t, ea_array);
%array_class(sel_t, sel_array);
%array_class(uval_t, uval_array);
%pointer_class(int, int_pointer);
%pointer_class(ea_t, ea_pointer);
%pointer_class(sval_t, sval_pointer);
%pointer_class(sel_t, sel_pointer);

%pythoncode %{
#<pycode(py_pro)>
#</pycode(py_pro)>
%}
