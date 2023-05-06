%{
#include <bitrange.hpp>
%}

%define %ptr_and_size_input(PTR, SIZE)
%typemap(in, fragment="outarg_cvt_bytevec_t") (PTR, SIZE) (bytevec_t tmp)
{
  // %typemap(in) (PTR, SIZE)
  if ( outarg_cvt_bytevec_t(&tmp, $input, /*can_be_none=*/ false) )
  {
    $1 = tmp.begin();
    $2 = tmp.size();
  }
  else
  {
    SWIG_exception_fail(
            SWIG_ValueError,
            "Expected bytes " "in method '" "$symname" "', argument " "$argnum"" of type 'bytes'");
  }
}
%enddef

//-------------------------------------------------------------------------
//
// bitrange_t::extract()
//
%ignore bitrange_t::extract(void *, size_t, const void *, size_t, bool) const;

%ptr_and_size_input(const void *src, size_t src_size);

%typemap(in, numinputs=0) bytevec_t *dst (bytevec_t tmp)
{
  // %typemap(in, numinputs=0) bytevec_t *dst (bytevec_t tmp)
  $1 = &tmp;
}

%typemap(freearg) bytevec_t *dst
{
  // %typemap(freearg) bytevec_t *dst
  // Nothing. We certainly don't want 'tmp' to be deleted.
}

%typemap(argout) bytevec_t *dst
{
  // %typemap(argout) bytevec_t *dst
  $result = _maybe_sized_binary_result(
        $result,
        (const char *) $1->begin(),
        $1->size(),
        result);
}

//-------------------------------------------------------------------------
//
// bitrange_t::inject()
//
%ignore bitrange_t::inject(void *, size_t, const void *, size_t, bool) const;

%ptr_and_size_input(void *dst, size_t dst_size);

%typemap(argout) (void *dst, size_t dst_size)
{
  // %typemap(argout) (void *dst, size_t dst_size)
  $result = _maybe_sized_binary_result(
        $result,
        (const char *) $1,
        $2,
        result);
}

//-------------------------------------------------------------------------
%extend bitrange_t {

  qstring __str__() const
  {
    qstring qs;
    qs.sprnt("{offset=%u, nbits=%u, [%u,%u), 0x%llx}",
             $self->bitoff(),
             $self->bitsize(),
             $self->bitoff(),
             $self->bitoff() + $self->bitsize(),
             $self->mask64());
    return qs;
  }
}

%include "bitrange.hpp"
