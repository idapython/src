%{
#include <dbg.hpp>
#include <loader.hpp>
%}

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

%ignore set_reg_val;
%rename (set_reg_val) py_set_reg_val;
%ignore request_set_reg_val;
%rename (request_set_reg_val) py_request_set_reg_val;
%rename (get_reg_val) py_get_reg_val;
%ignore get_reg_vals;
%rename (get_reg_vals) py_get_reg_vals;
%newobject py_get_reg_vals;

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

%ignore dbg_can_query;
%rename (dbg_can_query) py_dbg_can_query;

%define_regval_python_accessors();

//-------------------------------------------------------------------------
//                       get_process_options()
%define %get_process_options_out_qstring(ARG_NAME)
%typemap(in, numinputs=0) qstring *ARG_NAME (qstring temp)
{
  // %get_process_options_out_qstring %typemap(in, numinputs=0) qstring *ARG_NAME
  $1 = &temp;
}
%typemap(argout) qstring *ARG_NAME
{
  // %get_process_options_out_qstring %typemap(argout) qstring *ARG_NAME
  $result = SWIG_Python_AppendOutput($result, PyUnicode_FromString($1->c_str()));
}
%typemap(freearg) qstring* ARG_NAME
{
  // %get_process_options_out_qstring %typemap(freearg) qstring* ARG_NAME
  // Nothing. We certainly don't want 'temp' to be deleted.
}
%enddef
%get_process_options_out_qstring(path);
%get_process_options_out_qstring(args);
%get_process_options_out_qstring(sdir);
%get_process_options_out_qstring(host);
%get_process_options_out_qstring(pass);
%typemap(in, numinputs=0) launch_env_t *envs (launch_env_t temp)
{
  // %typemap(in, numinputs=0) launch_env_t *envs (launch_envs_t temp)
  $1 = &temp;
}
%apply int *OUTPUT { int *port };

// specialize for 'get_process_options()'s first output
// argument (i.e., 'path'), so we get rid of the 'None'
%typemap(argout) qstring *path
{
  // %typemap(argout) qstring *path (specialization)
  Py_XDECREF($result);
  $result = PyUnicode_FromString($1->c_str());
}

//-------------------------------------------------------------------------
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

// We want ALL wrappers around what is declared in dbg.hpp
// to release the GIL when calling into the IDA api: those
// might be very long operations, that even require some
// network traffic.
%include "dbg.hpp"
%nothread;
%define_Hooks_class(DBG);

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
  return PyUnicode_FromString(bpt->cndbody.c_str());
}

void bpt_t_condition_set(bpt_t *bpt, PyObject *val)
{
  if ( PyUnicode_Check(val) )
    PyUnicode_as_qstring(&bpt->cndbody, val);
  else
    PyErr_SetString(PyExc_ValueError, "expected a string");
}

PyObject *bpt_t_elang_get(bpt_t *bpt)
{
  return PyUnicode_FromString(bpt->get_cnd_elang());
}

void bpt_t_elang_set(bpt_t *bpt, PyObject *val)
{
  if ( PyUnicode_Check(val) )
  {
    qstring cval;
    PyUnicode_as_qstring(&cval, val);
    if ( !bpt->set_cnd_elang(cval.c_str()) )
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
    return PyBytes_FromStringAndSize(
        (const char *) $self->bytes.begin(),
        $self->bytes.size());
  }
  %pythoncode %{
    bytes = property(get_bytes)
  %}
}

%{
static bool _to_reg_val(regval_t **out, regval_t *buf, const char *name, PyObject *o);
static PyObject *_from_reg_val(
        const char *name,
        const regval_t &rv);
%}

%inline %{
//<inline(py_dbg)>
//</inline(py_dbg)>
%}

%{
//<code(py_dbg)>
//</code(py_dbg)>
%}

%pythoncode %{
#<pycode(py_dbg)>
#</pycode(py_dbg)>
%}
