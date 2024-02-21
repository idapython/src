%ignore rangeset_t::count;
%ignore rangeset_t::lower_bound;
%ignore rangeset_t::upper_bound;
%ignore rangeset_t::move_chunk;
%ignore rangeset_t::check_move_args;
%ignore range64_t;
%ignore range64vec_t;

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

     __len__ = nranges
     __iter__ = ida_idaapi._bounded_getitem_iterator
   }
};

%pythoncode %{
#<pycode(py_range)>
#</pycode(py_range)>
%}

%include "range.hpp"
