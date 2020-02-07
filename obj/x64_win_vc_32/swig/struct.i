%module(docstring="IDA Plugin SDK API wrapper: struct",directors="1",threads="1") ida_struct
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_STRUCT
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_STRUCT
  #define HAS_DEP_ON_INTERFACE_STRUCT
#endif
%include "header.i"
%{
#include <struct.hpp>
%}
// Kernel-only symbols
%ignore save_structs;
%ignore get_struc_name(tid_t);
%ignore get_member_name(tid_t);
%ignore get_member_by_id(tid_t, struc_t **); // allow version w/ qstring* only

//-------------------------------------------------------------------------
// For 'get_member_by_id()'
%typemap(in,numinputs=0) qstring *out_mname (qstring temp) {
  $1 = &temp;
}
%typemap(argout) qstring *out_mname {
  if (result)
  {
    %append_output(IDAPyStr_FromUTF8AndSize($1->begin(), $1->length()));
  }
  else
  {
    Py_XDECREF(resultobj);
    Py_INCREF(Py_None);
    resultobj = Py_None;
  }
}
%typemap(freearg) qstring* out_mname
{
  // Nothing. We certainly don't want 'temp' to be deleted.
}

//-------------------------------------------------------------------------
// For 'get_member_by_fullname()' and 'get_member_by_id()'
%typemap(in,numinputs=0) struc_t **sptr_place (struc_t *temp) {
  $1 = &temp;
}
%typemap(argout) struc_t **sptr_place {
  if ( result )
  {
    %append_output(SWIG_NewPointerObj(SWIG_as_voidptr(*($1)), SWIGTYPE_p_struc_t, 0 |  0 ));
  }
  else
  {
    Py_XDECREF(resultobj);
    Py_INCREF(Py_None);
    resultobj = Py_None;
  }
}

%nonnul_argument_prototype(
        asize_t get_member_size(const member_t *nonnul_mptr),
        const member_t *nonnul_mptr);

//-------------------------------------------------------------------------
%include "struct.hpp"
// Add a get_member() member function to struc_t.
// This helps to access the members array in the class.
%extend struc_t {
  member_t *get_member(int index) { return &(self->members[index]); }
}

%inline %{
//<inline(py_struct)>
//</inline(py_struct)>
%}
%pythoncode %{
if _BC695:
    get_member_name2=get_member_name
    def get_member_tinfo(*args):
        import ida_typeinf
        if isinstance(args[1], ida_typeinf.tinfo_t):  # 6.95: mptr, tinfo_t
            mptr, tif = args
        else:                                         # 7.00: tinfo_t, mptr
            tif, mptr = args
        return _ida_struct.get_member_tinfo(tif, mptr);
    def get_or_guess_member_tinfo(*args):
        import ida_typeinf
        if isinstance(args[1], ida_typeinf.tinfo_t):  # 6.95: mptr, tinfo_t
            mptr, tif = args
        else:                                         # 7.00: tinfo_t, mptr
            tif, mptr = args
        return _ida_struct.get_or_guess_member_tinfo(tif, mptr);
    # note: if needed we might have to re-implement get_member_tinfo()
    # and look whether there is a 2nd, 'tinfo_t' parameter (since the
    # original get_member_tinfo function has a different signature)
    get_member_tinfo2=get_member_tinfo
    # same here
    get_or_guess_member_tinfo2=get_or_guess_member_tinfo
    save_struc2=save_struc
    set_member_tinfo2=set_member_tinfo

%}