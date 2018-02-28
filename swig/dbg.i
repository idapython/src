%{
#include <dbg.hpp>
#include <loader.hpp>
%}

%import "idd.i"

%ignore dbg;
%ignore register_srcinfo_provider;
%ignore unregister_srcinfo_provider;
%ignore get_manual_regions;
%ignore internal_cleanup_appcall;
%ignore change_bptlocs;
%ignore movbpt_info_t;
%ignore lock_dbgmem_config;
%ignore unlock_dbgmem_config;

%ignore source_file_t;
%ignore source_item_t;
%ignore srcinfo_provider_t;
%ignore bpt_location_t::print;
%ignore bpt_t::set_cond;
%ignore bpt_t::eval_cond;
%ignore bpt_t::write;
%ignore bpt_t::erase;
%ignore bpt_t::cndbody;
%ignore bpt_t::get_cnd_elang;
%ignore bpt_t::set_cnd_elang;
%rename (get_manual_regions) py_get_manual_regions;
%ignore set_manual_regions;
// TODO: This could be fixed (if needed)
%ignore set_dbgmem_source;

%rename (list_bptgrps) py_list_bptgrps;
%apply qstring *result { qstring *grp_name };
%ignore qvector<bpt_t>::operator==;
%ignore qvector<bpt_t>::operator!=;
%ignore qvector<bpt_t>::find;
%ignore qvector<bpt_t>::has;
%ignore qvector<bpt_t>::del;
%ignore qvector<bpt_t>::add_unique;
%template(bpt_vec_t) qvector<bpt_t>;
%ignore write_dbg_memory;
%rename (write_dbg_memory) py_write_dbg_memory;

%ignore qvector<memreg_info_t>::operator==;
%ignore qvector<memreg_info_t>::operator!=;
%ignore qvector<memreg_info_t>::find;
%ignore qvector<memreg_info_t>::has;
%ignore qvector<memreg_info_t>::del;
%ignore qvector<memreg_info_t>::add_unique;
%ignore memreg_info_t::bytes;
%rename (bytes) memreg_info_t_py_bytes;
%template(memreg_infos_t) qvector<memreg_info_t>;

%ignore internal_get_sreg_base;
%rename (internal_get_sreg_base) py_internal_get_sreg_base;

// KLUDGE: since dbg.hpp has first declarations, then definitions
// of inline functions, and SWiG only sees the 2nd part, which
// doesn't have the default argument values, we want to provide
// them here. The proper fix is of course to re-hash dbg.hpp
// so that we avoid this decl + def, and only keep the definitions.
bool run_to(ea_t ea, pid_t pid = NO_PROCESS, thid_t tid = NO_THREAD);
bool request_run_to(ea_t ea, pid_t pid = NO_PROCESS, thid_t tid = NO_THREAD);

%thread;

%nonnul_argument_prototype(
        inline bool idaapi load_debugger(const char *nonnul_dbgname, bool use_remote),
        const char *nonnul_dbgname);
%nonnul_argument_prototype(
        inline void idaapi set_debugger_event_cond(const char *nonnul_cond),
        const char *nonnul_cond);
%nonnul_argument_prototype(
        inline bool idaapi diff_trace_file(const char *nonnul_filename),
        const char *nonnul_filename);

// We want ALL wrappers around what is declared in dbg.hpp
// to release the GIL when calling into the IDA api: those
// might be very long operations, that even require some
// network traffic.
%include "dbg.hpp"
%nothread;
%ignore DBG_Callback;
%ignore DBG_Hooks::store_int;

%{
//<code(py_dbg)>
//</code(py_dbg)>
%}

//-------------------------------------------------------------------------
//                                 bpt_t
//-------------------------------------------------------------------------
%extend bpt_t
{
  PyObject *condition;
  PyObject *elang;
}

%{
PyObject *bpt_t_condition_get(bpt_t *bpt)
{
  return PyString_FromString(bpt->cndbody.c_str());
}

void bpt_t_condition_set(bpt_t *bpt, PyObject *val)
{
  if ( PyString_Check(val) )
    bpt->cndbody = PyString_AsString(val);
  else
    PyErr_SetString(PyExc_ValueError, "expected a string");
}

PyObject *bpt_t_elang_get(bpt_t *bpt)
{
  return PyString_FromString(bpt->get_cnd_elang());
}

void bpt_t_elang_set(bpt_t *bpt, PyObject *val)
{
  if ( PyString_Check(val) )
  {
    char *cval = PyString_AsString(val);
    if ( !bpt->set_cnd_elang(cval) )
      PyErr_SetString(PyExc_ValueError, "too many extlangs");
  }
  else
  {
    PyErr_SetString(PyExc_ValueError, "expected a string");
  }
}
%}

//-------------------------------------------------------------------------
//                              memreg_info_t
//-------------------------------------------------------------------------
%extend memreg_info_t
{
  PyObject *get_bytes() const
  {
    return PyString_FromStringAndSize(
        (const char *) $self->bytes.begin(),
        $self->bytes.size());
  }
  %pythoncode %{
    bytes = property(get_bytes)
  %}
}

%inline %{
//<inline(py_dbg)>
//</inline(py_dbg)>
%}

%pythoncode %{
#<pycode(py_dbg)>
#</pycode(py_dbg)>
%}
