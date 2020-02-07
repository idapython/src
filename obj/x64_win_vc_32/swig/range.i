%module(docstring="IDA Plugin SDK API wrapper: range",directors="1",threads="1") ida_range
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_RANGE
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_RANGE
  #define HAS_DEP_ON_INTERFACE_RANGE
#endif
%include "header.i"
%ignore rangeset_t::count;
%ignore rangeset_t::lower_bound;
%ignore rangeset_t::upper_bound;
%ignore rangeset_t::move_chunk;
%ignore rangeset_t::check_move_args;

%template(rangevec_base_t) qvector<range_t>;
%template(array_of_rangesets) qvector<rangeset_t>;

%inline %{
//<inline(py_range)>
//</inline(py_range)>
%}

%extend rangeset_t {
   %pythoncode {
     def __getitem__(self, idx):
         return self.getrange(idx)

     import ida_idaapi
     __len__ = nranges
     __iter__ = ida_idaapi._bounded_getitem_iterator
   }
};

%include "range.hpp"
%pythoncode %{
if _BC695:
    import sys
    sys.modules["ida_area"] = sys.modules["ida_range"]
    area_t = range_t
    areaset_t = rangeset_t
    def __set_startEA(inst, v):
        inst.start_ea = v
    range_t.startEA = property(lambda self: self.start_ea, __set_startEA)
    def __set_endEA(inst, v):
        inst.end_ea = v
    range_t.endEA = property(lambda self: self.end_ea, __set_endEA)

%}