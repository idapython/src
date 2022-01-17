// Ignore kernel-only functions and variables
%ignore create_xrefs_from;
%ignore delete_all_xrefs_from;
%ignore destroy_if_align;
%ignore lastXR;
%ignore create_switch_xrefs;
%rename (create_switch_xrefs) py_create_switch_xrefs;
%ignore create_switch_table;
%rename (create_switch_table) py_create_switch_table;
%ignore calc_switch_cases;
%rename (calc_switch_cases)   py_calc_switch_cases;

// These functions should not be called directly (according to docs)
%ignore xrefblk_t_first_from;
%ignore xrefblk_t_next_from;
%ignore xrefblk_t_first_to;
%ignore xrefblk_t_next_to;

// 'from' is a reserved Python keyword
%rename (frm) from;


%define %def_simple_generator(FUNC_NAME, START_FUNC, NEXT_FUNC, PYDOC)
%extend xrefblk_t
{
  %pythoncode {
    def FUNC_NAME(self, ea):
        """
        Provide an iterator on PYDOC
        """
        ref = START_FUNC(ea)
        while ref != ida_idaapi.BADADDR:
            yield ref
            ref = NEXT_FUNC(ea, ref)
  }
}
%enddef

%def_simple_generator(crefs_to, get_first_cref_to, get_next_cref_to, code references to ea including flow references);
%def_simple_generator(fcrefs_to, get_first_fcref_to, get_next_fcref_to, code references to ea);
%def_simple_generator(crefs_from, get_first_cref_from, get_next_cref_from, code references from ea including flow references);
%def_simple_generator(fcrefs_from, get_first_fcref_from, get_next_fcref_from, code references from ea);
%def_simple_generator(drefs_to, get_first_dref_to, get_next_dref_to, data references to ea);
%def_simple_generator(drefs_from, get_first_dref_from, get_next_dref_from, data references from ea);


%define %def_generic_generator(FUNC_NAME, START_FUNC, NEXT_FUNC, PYDOC)
%extend xrefblk_t
{
  %pythoncode {
    def FUNC_NAME(self, ea, flag):
        """
        Provide an iterator on PYDOC
        """
        def _copy_xref():
            """ Make a private copy of the xref class to preserve its contents """
            class _xref(object):
                pass

            xr = _xref()
            for attr in [ 'frm', 'to', 'iscode', 'type', 'user' ]:
                setattr(xr, attr, getattr(self, attr))
            return xr

        if self.START_FUNC(ea, flag):
            yield _copy_xref()
            while self.NEXT_FUNC():
                yield _copy_xref()
  }
}
%enddef
%def_generic_generator(refs_from, first_from, next_from, from reference represented by flag );
%def_generic_generator(refs_to, first_to, next_to, to reference represented by flag );

%inline %{
//<inline(py_xref)>
//</inline(py_xref)>
%}

%include "xref.hpp"

%template(casevec_t) qvector<qvector<sval_t> >; // signed values

%pythoncode %{
#<pycode(py_xref)>
#</pycode(py_xref)>
%}
