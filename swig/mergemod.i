
%{
#include <mergemod.hpp>
%}

%ignore create_std_modmerge_handlers;
%rename(create_std_modmerge_handlers) create_std_modmerge_handlers2;

// Prototype of the custom function to create merge handlers
%ignore create_merge_handlers;

// idaman void ida_export create_std_modmerge_handlers2(
//         merge_handler_params_t &mhp,
//         int moddata_id,
//         moddata_diff_helper_t &helper,
//         const merge_node_info2_t *merge_node_info=nullptr,
//         size_t n_merge_node_info=0);
%typemap(in,numinputs=0) (int moddata_id) { $1 = -1; }
%typemap(in,numinputs=1) (const merge_node_info2_t *merge_node_info, size_t n_merge_node_info) (qvector<merge_node_info2_t> temp)
{
  if ( $input == Py_None )
  {
    $2 = 0;
    $1 = nullptr;
  }
  else
  {
    if ( !PySequence_Check($input) )
    {
      PyErr_SetString(PyExc_TypeError, "Expecting a list of `merge_node_info2_t` instances");
      return nullptr;
    }
    PyObject *s = $input;
    Py_ssize_t len = PySequence_Size(s);
    temp.reserve(len);
    for ( Py_ssize_t i = 0; i < len; ++i )
    {
      newref_t o(PySequence_GetItem(s, i));
      void *ap = 0 ;
      int cvt = SWIG_ConvertPtr(o.o, &ap, SWIGTYPE_p_merge_node_info2_t, 0);
      if ( !SWIG_IsOK(cvt) )
        SWIG_exception_fail(
                SWIG_ArgError(cvt),
                "in method '" "$symname" "', argument " "$argnum"" consists of 'merge_node_info2_t' instances");
      temp.push_back(*reinterpret_cast<merge_node_info2_t*>(ap));
    }
    $2 = temp.size();
    $1 = temp.extract();
  }
}

%include "mergemod.hpp"

