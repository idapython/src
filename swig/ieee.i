
%{
#include <ieee.h>
%}

%ignore ieee_ezero;
%ignore ieee_eone;
%ignore ieee_etwo;
%ignore ieee_e32;
%ignore ieee_elog2;
%ignore ieee_esqrt2;
%ignore ieee_eoneopi;
%ignore ieee_epi;
%ignore ieee_eeul;
%ignore realtoasc;
%ignore asctoreal;
%ignore eltoe;
%ignore eltoe64;
%ignore eltoe64u;
%ignore eetol;
%ignore eetol64;
%ignore eetol64u;
%ignore eldexp;
%ignore eadd;
%ignore emul;
%ignore ediv;
%ignore ecmp;
%ignore get_fpvalue_kind;
%ignore emovo;
%ignore emovi;
%ignore eshift;
%ignore emdnorm;
%ignore ieee_realcvt;
%ignore realcvt;
%ignore l_realcvt;
%ignore b_realcvt;

%typemap(argout) (char *buf, size_t bufsize)
{
  // %typemap(argout) (char *buf, size_t bufsize) (ieee.i specialization)
  Py_XDECREF(resultobj);
  $result = PyUnicode_FromString($1);
}

%_uint_result_as_output(sval_t, PyLong_FromLong, result == REAL_ERROR_OK);
%_uint_result_as_output(int64, PyLong_FromLongLong, result == REAL_ERROR_OK);
%_uint_result_as_output(uint64, PyLong_FromUnsignedLongLong, result == REAL_ERROR_OK);
%apply sval_t *result { sval_t *out };
%apply int64 *result { int64 *out };
%apply uint64 *result { uint64 *out };

%inline %{
//<inline(py_ieee)>
//</inline(py_ieee)>
%}

%define %define_sized_bytevec_t(TYPE, SIZE)
%typemap(check) (const TYPE &)
{ // %typemap(check) (const TYPE)
  if ( $1->size() != SIZE )
    SWIG_exception_fail(
            SWIG_ValueError,
            "invalid bytes " "in method '" "$symname" "', argument " "$argnum"" should be " #SIZE " bytes long");
}
%enddef
%define_sized_bytevec_t(bytevec12_t, 12);
%define_sized_bytevec_t(bytevec10_t, 10);

%ignore fpvalue_t::from_half;
%ignore fpvalue_t::from_float;
%ignore fpvalue_t::from_double;
%ignore fpvalue_t::to_half;
%ignore fpvalue_t::to_float;
%ignore fpvalue_t::to_double;
%ignore fpvalue_t::from_str(const char **);

%template (fpvalue_shorts_array_t) wrapped_array_t<uint16,FPVAL_NWORDS>;

%extend fpvalue_t {
  fpvalue_t()
  {
    fpvalue_t *fp = new fpvalue_t();
    fp->clear();
    return fp;
  }

  fpvalue_t(const bytevec12_t &in)
  {
    fpvalue_t *fp = new fpvalue_t();
    memmove(fp->w, in.begin(), sizeof(fp->w));
    return fp;
  }

  void _get_bytes(bytevec12_t *vout) const
  {
    vout->resize(12);
    memmove(vout->begin(), (const void *) $self->w, vout->size());
  }

  void _set_bytes(const bytevec12_t &in)
  {
    memmove($self->w, (const void *) in.begin(), sizeof($self->w));
  }

  void _get_10bytes(bytevec10_t *vout) const
  {
    vout->resize(10);
    memmove(vout->begin(), (const void *) $self->w, vout->size());
  }

  void _set_10bytes(const bytevec10_t &in)
  {
    CASSERT(sizeof($self) == 10);
    memmove($self->w, (const void *) in.begin(), in.size()); // guaranteed to be 10 bytes long, thanks to %typemap(check) (const bytevec10_t)
    $self->w[FPVAL_NWORDS-1] = 0;
  }

  // yes, it's called '_get_float', but we return a 'double' because
  // that 'double' will be for SWiG to turn the type into a Python
  // floating-point value with as much accuracy as possible.
  double _get_float() const
  {
    double v;
    fpvalue_error_t err = $self->to_double(&v);
    if ( err != REAL_ERROR_OK )
      PyErr_SetString(
              PyExc_ValueError,
              "Raw data couldn't be converted to a floating-point number");
    return v;
  }

  void _set_float(double v)
  {
    fpvalue_error_t err = $self->from_double(v);
    if ( err != REAL_ERROR_OK )
      PyErr_SetString(
              PyExc_ValueError,
              "The floating-point number couldn't be converted");
  }

  qstring __str__() const
  {
    char buf[MAXSTR];
    $self->to_str(buf, sizeof(buf), 50);
    qstring qs(buf);
    qs.trim2();
    return qs;
  }

  wrapped_array_t<uint16,FPVAL_NWORDS> _get_shorts()
  {
    return wrapped_array_t<uint16,FPVAL_NWORDS>($self->w);
  }

  fpvalue_error_t from_str(const char *p)
  {
    return p != nullptr ? $self->from_str(&p) : REAL_ERROR_BADSTR;
  }

  void assign(const fpvalue_t &r)
  {
    memmove($self->w, r.w, sizeof($self->w));
  }

  %pythoncode
  {
    bytes = property(_get_bytes, _set_bytes)
    _10bytes = property(_get_10bytes, _set_10bytes)
    shorts = property(_get_shorts)
    float = property(_get_float, _set_float)
    sval = property(lambda self: self.to_sval(), lambda self, v: self.from_sval(v))
    int64 = property(lambda self: self.to_int64(), lambda self, v: self.from_int64(v))
    uint64 = property(lambda self: self.to_uint64(), lambda self, v: self.from_uint64(v))

    def __iter__(self):
        shorts = self.shorts
        for one in shorts:
            yield one

    def __getitem__(self, i):
        return self.shorts[i]

    def __setitem__(self, i, v):
        self.shorts[i] = v
  }
}

%define %define_fpvalue_t_operator(OPERATOR, METHOD, ERRMSG)
%nopythonmaybecall fpvalue_t::OPERATOR;
%extend fpvalue_t {
  fpvalue_t OPERATOR(const fpvalue_t &o) const
  {
    fpvalue_t r = *$self;
    fpvalue_error_t err = r.METHOD(o);
    if ( err != REAL_ERROR_OK )
      throw std::runtime_error(ERRMSG);
    return r;
  }
}
%enddef
%define_fpvalue_t_operator(__add__, fadd, "Addition failed");
%define_fpvalue_t_operator(__sub__, fsub, "Subtraction failed");
%define_fpvalue_t_operator(__mul__, fmul, "Multiplication failed");
%define_fpvalue_t_operator(__truediv__, fdiv, "Division failed");

%include "ieee.h"

%pythoncode %{
#<pycode(py_ieee)>
#</pycode(py_ieee)>
%}
