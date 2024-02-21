
%{
#include <merge.hpp>
%}
// diff3.hpp 
typedef int diff_source_idx_t;

%ignore merge_node_info_t;
%rename(merge_node_info_t) merge_node_info2_t;
%ignore create_nodeval_merge_handler;
%rename(create_nodeval_merge_handler) create_nodeval_merge_handler2;
%ignore create_nodeval_merge_handlers;
%rename(create_nodeval_merge_handlers) create_nodeval_merge_handlers2;

// for dump_merge_results() only
%ignore merge_node_helper_t::get_logname;
// FIXME: do not know how to handle
%ignore merge_node_helper_t::map_value;

// for C++ only, hide kernel data
%ignore merge_data_t::mappers;

// void merge_data_t::operator=(const merge_data_t&) = deleted
%immutable merge_handler_params_t::md;

// kernel only
%ignore MH_DUMMY;

// no need to create new instances
%feature("nodirector") merge_data_t;
%ignore merge_data_t::merge_data_t;
%ignore merge_data_t::~merge_data_t;

%typemap(check) (const char *_module_name) (qstring tmp) {
  tmp = $1;
  $1 = tmp.extract();
}

%typemap(check) (const char *_netnode_name) (qstring tmp) {
  tmp = $1;
  $1 = tmp.extract();
}

%typemap(in,numinputs=1) (const idbattr_info_t *_fields, size_t _nfields) (qvector<idbattr_info_t> temp)
{
  if ( !PySequence_Check($input) )
  {
    PyErr_SetString(PyExc_TypeError, "Expecting a list of `idbattr_info_t` instances");
    return nullptr;
  }
  PyObject *s = $input;
  Py_ssize_t len = PySequence_Size(s);
  temp.reserve(len);
  for ( Py_ssize_t i = 0; i < len; ++i )
  {
    newref_t o(PySequence_GetItem(s, i));
    void *ap = 0 ;
    int cvt = SWIG_ConvertPtr(o.o, &ap, SWIGTYPE_p_idbattr_info_t, 0);
    if ( !SWIG_IsOK(cvt) )
      SWIG_exception_fail(
              SWIG_ArgError(cvt),
              "in method '" "$symname" "', argument " "$argnum"" consists of 'idbattr_info_t' instances");
    temp.push_back(*reinterpret_cast<idbattr_info_t*>(ap));
  }
  $2 = temp.size();
  $1 = temp.extract();
}

%define_netnode_tag_accessors();

%extend merge_node_info2_t
{
  /// \param name         name of the array (label)
  /// \param tag          a tag used to access values in the netnode
  /// \param nds_flags    node value attributes (a combination of \ref nds_flags_t)
  /// \param node_helper  merge handler creation helper
  merge_node_info2_t(
        const char *name,
        uchar tag,
        uint32 nds_flags,
        merge_node_helper_t *node_helper=nullptr)
  {
    merge_node_info2_t *ii = new merge_node_info2_t();
    ii->name = name == nullptr ? nullptr : qstrdup(name);
    ii->tag = tag;
    ii->nds_flags = nds_flags;
    ii->node_helper = node_helper;
    return ii;
  }

  ~merge_node_info2_t()
  {
    qfree((char *) $self->name);
    delete $self;
  }
}

// For:
//   merge_node_helper_t::print_entry_details
//   merge_node_helper_t::get_column_headers
%typemap(directorargout) qstrvec_t * (qstrvec_t tmp)
{ // %typemap(directorargout) qstrvec_t *
  if ( $result != Py_None )
  {
    if ( PyW_PySeqToStrVec(&tmp, $result) >= 0 )
    {
      $1->insert($1->end(), tmp.begin(), tmp.end());
    }
    else
    {
      Swig::DirectorTypeMismatchException::raise(
        SWIG_ErrorType(SWIG_TypeError),
        "in output value of type 'qstrvec_t' in method '$symname'");
    }
  }
}

// idaman void ida_export create_nodeval_merge_handlers2(
//         merge_handlers_t *out,
//         const merge_handler_params_t &mhp,
//         int moddata_id,
//         const char *nodename,
//         const merge_node_info2_t *valdesc,
//         size_t nvals,
//         bool skip_empty_nodes = true);
%typemap(in,numinputs=0) (int moddata_id) { $1 = -1; }
%typemap(in,numinputs=1) (const merge_node_info2_t *valdesc, size_t nvals) (qvector<merge_node_info2_t> temp)
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

%include "merge.hpp"
