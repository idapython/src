//---------------------------------------------------------------------
%typemap(out) uint64 {
$result = PyLong_FromUnsignedLongLong((unsigned long long) $1);
}

//---------------------------------------------------------------------
%typemap(in) uint64
{
  uint64 $1_temp;
  if ( !PyW_GetNumber($input, &$1_temp) )
  {
    PyErr_SetString(PyExc_TypeError, "Expected an uint64 type");
    return NULL;
  }
  $1 = $1_temp;
}

//---------------------------------------------------------------------

%ignore wchar2char;
%ignore hit_counter_t;
%ignore reg_hit_counter;
%ignore create_hit_counter;
%ignore hit_counter_timer;
%ignore print_all_counters;
%ignore incrementer_t;
%ignore reloc_info_t; // swig under mac chokes on this
%ignore qmutex_create;
%ignore qiterator;
%ignore qmutex_free;
%ignore qmutex_lock;
%ignore qmutex_t;
%ignore qmutex_unlock;
%ignore qsem_create;
%ignore qsem_free;
%ignore qsem_post;
%ignore qsem_wait;
%ignore qsemaphore_t;
%ignore qthread_cb_t;
%ignore qthread_create;
%ignore qthread_free;
%ignore qthread_join;
%ignore qthread_kill;
%ignore qthread_self;
%ignore qthread_same;
%ignore qthread_t;
%ignore qhandle_t;
%ignore qpipe_create;
%ignore qpipe_read;
%ignore qpipe_write;
%ignore qpipe_close;
%ignore qwait_for_handles;
%ignore qstrlen;
%ignore qstrcmp;
%ignore qstrstr;
%ignore qstrchr;
%ignore qstrrchr;
%ignore bytevec_t;
%ignore qstrvec_t;
%ignore reloc_info_t;
%ignore relobj_t;
%ignore wchar2char;
%ignore u2cstr;
%ignore c2ustr;
%ignore base64_encode;
%ignore base64_decode;
%ignore utf8_unicode;
%ignore unicode_utf8;
%ignore win_utf2idb;
%ignore char2oem;
%ignore oem2char;
%ignore set_codepages;
%ignore get_codepages;
%ignore convert_codepage;
%ignore test_bit;
%ignore set_bit;
%ignore clear_bit;
%ignore set_all_bits;
%ignore clear_all_bits;
%ignore interval::overlap;
%ignore interval::includes;
%ignore interval::contains;
%ignore qrotl;
%ignore qrotr;
%ignore setflag;
%ignore read2bytes;
%ignore rotate_left;
//%ignore qswap;
%ignore swap32;
%ignore swap16;
%ignore swap_value;
%ignore qalloc_or_throw;
%ignore qrealloc_or_throw;
%ignore get_buffer_for_sysdir;
%ignore get_buffer_for_winerr;
%ignore call_atexits;
%ignore launch_process_params_t;
%ignore launch_process;
%ignore term_process;
%ignore get_process_exit_code;
%ignore BELOW_NORMAL_PRIORITY_CLASS;
%ignore parse_command_line;
%ignore parse_command_line2;
%ignore parse_command_line3;
%rename (parse_command_line3) py_parse_command_line;
%ignore qgetenv;
%ignore qsetenv;
%ignore qctime;
%ignore qlocaltime;
%ignore qstrftime;
%ignore qstrftime64;
%ignore qstrtok;
%ignore qstrlwr;
%ignore qstrupr;

void qvector<uval_t>::grow(const unsigned int &x=0);
%ignore qvector<uval_t>::grow;
%ignore qvector::at(size_t);

// simpleline_t doesn't implement '=='. Therefore, all these cannot be present in the instantiated template.
%ignore qvector<simpleline_t>::operator==;
%ignore qvector<simpleline_t>::operator!=;
%ignore qvector<simpleline_t>::find;
%ignore qvector<simpleline_t>::has;
%ignore qvector<simpleline_t>::del;
%ignore qvector<simpleline_t>::add_unique;

%include "pro.h"

//---------------------------------------------------------------------
%extend qvector {
  inline size_t __len__() const { return $self->size(); }

  // The fact that we are returning a const version of a reference to the
  // type is what allows SWIG to generate a wrapper for this method, that
  // will build an proper object (int, unsigned int, ...) instead
  // of a pointer. Remove the 'const', and you'll see that, in
  // SWIGINTERN PyObject *_wrap_uvalvec_t___getitem__(PyObject *SWIGUNUSEDPARM(self), PyObject *args) {
  // it will produce this:
  //    resultobj = SWIG_NewPointerObj(SWIG_as_voidptr(result), SWIGTYPE_p_unsigned_int, 0 |  0 );
  // instead of that:
  //    resultobj = SWIG_From_unsigned_SS_int(static_cast< unsigned int >(*result));
  inline const T& __getitem__(size_t i) const throw(std::out_of_range) {
    if (i >= $self->size() || i < 0)
      throw std::out_of_range("out of bounds access");
    return $self->at(i);
  }

  inline void __setitem__(size_t i, const T& v) throw(std::out_of_range) {
    if (i >= $self->size() || i < 0)
      throw std::out_of_range("out of bounds access");
    $self->at(i) = v;
  }

  %pythoncode {
    __iter__ = _bounded_getitem_iterator
  }
}

//---------------------------------------------------------------------
%template(uvalvec_t) qvector<uval_t>; // unsigned values
%template(intvec_t)  qvector<int>;
%template(boolvec_t) qvector<bool>;
%template(casevec_t) qvector<qvector<sval_t> >; // signed values
%template(strvec_t)  qvector<simpleline_t>;

%pythoncode %{
_listify_types(uvalvec_t,
               intvec_t,
               boolvec_t,
               casevec_t,
               strvec_t)
%}
