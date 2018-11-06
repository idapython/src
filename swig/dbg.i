%{
#include <dbg.hpp>
#include <loader.hpp>
%}

%import "idd.i"

%ignore dbg;
%ignore register_srcinfo_provider;
%ignore unregister_srcinfo_provider;
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
// TODO: This could be fixed (if needed)
%ignore set_dbgmem_source;

// unusable functions because 'dbg' is not available:
%ignore have_set_options;
%ignore set_dbg_options;
%ignore set_int_dbg_options;
%ignore set_dbg_default_options;

/* %ignore invalidate_dbg_state; */
/* %ignore is_request_running; */

%rename (list_bptgrps) py_list_bptgrps;
%apply qstring *result { qstring *grp_name };
%uncomparable_elements_qvector(bpt_t, bpt_vec_t);

%ignore write_dbg_memory;
%rename (write_dbg_memory) py_write_dbg_memory;

%uncomparable_elements_qvector(tev_reg_value_t, tev_reg_values_t);
%uncomparable_elements_qvector(tev_info_reg_t, tevinforeg_vec_t);
%ignore memreg_info_t::bytes;
%rename (bytes) memreg_info_t_py_bytes;
%uncomparable_elements_qvector(memreg_info_t, memreg_infos_t);

%ignore internal_get_sreg_base;
%rename (internal_get_sreg_base) py_internal_get_sreg_base;

// KLUDGE: since dbg.hpp has first declarations, then definitions
// of inline functions, and SWiG only sees the 2nd part, which
// doesn't have the default argument values, we want to provide
// them here. The proper fix is of course to re-hash dbg.hpp
// so that we avoid this decl + def, and only keep the definitions.
bool run_to(ea_t ea, pid_t pid = NO_PROCESS, thid_t tid = NO_THREAD);
bool request_run_to(ea_t ea, pid_t pid = NO_PROCESS, thid_t tid = NO_THREAD);

%ignore get_insn_tev_reg_val(int, const char *, uint64 *);
%ignore get_insn_tev_reg_result(int, const char *, uint64 *);

%thread;

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
