%{
#include <idd.hpp>
#include <dbg.hpp>
#include <ua.hpp>
#include <err.h>
%}

%ignore debugger_t::init_debugger(char const *,int,char const *);
%ignore debugger_t::get_processes(procinfo_vec_t *);
%ignore debugger_t::start_process(char const *,char const *,launch_env_t *,char const *,uint32,char const *,uint32);
%ignore debugger_t::attach_process(pid_t,int,uint32);
%ignore debugger_t::detach_process();
%ignore debugger_t::request_pause();
%ignore debugger_t::exit_process();
%ignore debugger_t::resume(debug_event_t const *);
%ignore debugger_t::thread_suspend(thid_t);
%ignore debugger_t::thread_continue(thid_t);
%ignore debugger_t::set_resume_mode(thid_t,resume_mode_t);
%ignore debugger_t::read_registers(thid_t,int,regval_t *);
%ignore debugger_t::write_register(thid_t,int,regval_t const *);
%ignore debugger_t::thread_get_sreg_base(ea_t *,thid_t,int);
%ignore debugger_t::get_memory_info(meminfo_vec_t &);
%ignore debugger_t::read_memory(size_t *,ea_t,void *,size_t);
%ignore debugger_t::write_memory(size_t *,ea_t,void const *,size_t);
%ignore debugger_t::update_bpts(int *,update_bpt_info_t *,int,int);
%ignore debugger_t::update_lowcnds(int *,lowcnd_t const *,int);
%ignore debugger_t::open_file(char const *,uint64 *,bool);
%ignore debugger_t::read_file(int,qoff64_t,void *,size_t);
%ignore debugger_t::write_file(int,qoff64_t,void const *,size_t);
%ignore debugger_t::eval_lowcnd(thid_t,ea_t);
%ignore debugger_t::send_ioctl(int,void const *,size_t,void **,ssize_t *);
%ignore debugger_t::bin_search(ea_t *,ea_t,ea_t,compiled_binpat_vec_t const &,int);

%ignore dynamic_register_set_t;
%ignore serialize_dynamic_register_set;
%ignore deserialize_dynamic_register_set;
%ignore serialize_insn;
%ignore deserialize_insn;
%ignore free_debug_event;
%ignore copy_debug_event;
%ignore debugger_t::set_dbg_options;
%ignore debugger_t::callback;
%ignore debugger_t::notify;
%ignore debugger_t::notify_drc;
%ignore debugger_t::registers;
%ignore debugger_t::nregisters;
%ignore debugger_t::regclasses;
%ignore debugger_t::bpt_bytes;
%ignore debugger_t::default_port_number;
%ignore register_info_t::bit_strings;
%ignore lowcnd_t;
%ignore lowcnd_vec_t;
%ignore update_bpt_info_t;
%ignore update_bpt_vec_t;
%ignore appcall;
%ignore idd_opinfo_t;
%ignore gdecode_t;
%ignore memory_buffer_t;

%ignore debug_event_t::exit_code();
%ignore debug_event_t::bpt() const;
%ignore debug_event_t::exc() const;
%ignore debug_event_t::info() const;
%ignore debug_event_t::modinfo() const;

%ignore append_regval;
%ignore extract_regvals;
%ignore unpack_regvals;
%apply unsigned char { op_dtype_t dtype };
%ignore regval_t::_set_int;
%ignore regval_t::_set_float;
%ignore regval_t::_set_bytes;
%ignore regval_t::_set_unavailable;

%uncomparable_elements_qvector(exception_info_t, excvec_t);
%uncomparable_elements_qvector(process_info_t, procinfo_vec_t);
%template(call_stack_info_vec_t) qvector<call_stack_info_t>;
%template(meminfo_vec_template_t) qvector<memory_info_t>;
%template(regvals_t) qvector<regval_t>;

%define_regval_python_accessors();

%include "idd.hpp"

%clear(op_dtype_t dtype);

%rename (appcall) py_appcall;

//-------------------------------------------------------------------------
%template (dyn_register_info_array) dynamic_wrapped_array_t<register_info_t>;
%extend debugger_t
{
  dynamic_wrapped_array_t<register_info_t> __get_registers()
  {
    return dynamic_wrapped_array_t<register_info_t>($self->registers, $self->nregisters);
  }

  int __get_nregisters()
  {
    return $self->nregisters;
  }

  PyObject *__get_regclasses()
  {
    qstrvec_t rcs;
    const char *const *clsptr = $self->regclasses;
    for ( ; *clsptr != nullptr; ++clsptr )
      rcs.push_back(*clsptr);
    return qstrvec2pylist(rcs);
  }

  bytevec_t __get_bpt_bytes()
  {
    bytevec_t bv;
    bv.resize($self->bpt_size);
    memmove(bv.begin(), $self->bpt_bytes, bv.size());
    return bv;
  }

  %pythoncode {
    registers = property(__get_registers)
    nregisters = property(__get_nregisters)
    regclasses = property(__get_regclasses)
    bpt_bytes = property(__get_bpt_bytes)
  }
}

//-------------------------------------------------------------------------
%extend regval_t
{
  bool set_pyval(PyObject *o, op_dtype_t dtype)
  {
    regval_t buf;
    regval_t *ptr;
    bool ok = set_regval_t(&ptr, &buf, dtype, o);
    if ( ok )
      *$self = buf;
    return ok;
  }

  PyObject *pyval(op_dtype_t dtype)
  {
    return get_regval_t(*$self, dtype);
  }
}

//-------------------------------------------------------------------------
%extend register_info_t
{
  PyObject *__get_bit_strings()
  {
    if ( ($self->flags & REGISTER_CUSTFMT) == 0 && $self->bit_strings != nullptr )
    {
      const int nbits = get_dtype_size($self->dtype) * 8;
      qstrvec_t bss;
      bss.reserve(nbits);
      for ( int i = 0; i < nbits; ++i )
        bss.push_back($self->bit_strings[i] != nullptr ? $self->bit_strings[i] : "");
      return qstrvec2pylist(bss, S2LF_EMPTY_NONE);
    }
    else
    {
      Py_RETURN_NONE;
    }
  }

  %pythoncode {
    bit_strings = property(__get_bit_strings)
  }
}

//-------------------------------------------------------------------------
%extend launch_env_t
{
  void set(const char *envvar, const char *value)
  {
    qstring envline = envvar;
    envline += "=";
    envline += value;
    $self->push_back(envline);
  }

  PyObject *envs()
  {
    return qstrvec2pylist(*$self, S2LF_EMPTY_NONE);
  }
}

%{
//<code(py_idd)>
//</code(py_idd)>
%}

%inline %{
//<inline(py_idd)>
//</inline(py_idd)>
%}

%pythoncode %{
#<pycode(py_idd)>
#</pycode(py_idd)>
%}
