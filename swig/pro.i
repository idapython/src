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
%ignore reloc_info_t;
%ignore relobj_t;
%ignore wchar2char;
%ignore u2cstr;
%ignore c2ustr;
%ignore base64_encode;
%ignore base64_decode;
%ignore utf8_unicode;
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
%ignore qswap;
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
%rename (parse_command_line2) py_parse_command_line;
%ignore qgetenv;
%ignore qsetenv;
%ignore qctime;
%ignore qlocaltime;
%ignore qstrftime;
%ignore qstrftime64;
%ignore qstrtok;
%ignore qstrlwr;
%ignore qstrupr;
%include "pro.h"

//---------------------------------------------------------------------
%template(uvalvec_t) qvector<uval_t>;    // vector of unsigned values
%template(intvec_t)  qvector<int>;       // vector of integers
%template(qstrvec_t) qvector<qstring>;   // vector of strings
%template(boolvec_t) qvector<bool>;      // vector of bools

//---------------------------------------------------------------------
class qstring {
public:
    const char *c_str() const { return self->c_str(); }
};

//---------------------------------------------------------------------
// for obscure reasons swig can't get past this one on its own, it needs a dummy declaration.
class strvec_t {
public:
    qstring& at(int _idx) { return self->at(_idx).line; }
    size_t size() const { return self->size(); }
};

class qtype {
public:
    const uchar *c_str() const { return self->c_str(); }
};
