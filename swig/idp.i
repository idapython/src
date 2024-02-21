%{
#include <idp.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <auto.hpp>
#include <fixup.hpp>
#include <tryblks.hpp>
#include <idacfg.hpp>

struct undo_records_t;
%}

%import "bitrange.hpp"

// Ignore the following symbols
%ignore rginfo;
%ignore processor_t::is_canon_insn;
%ignore bytes_t;
%ignore IDPOPT_STR;
%ignore IDPOPT_NUM;
%ignore IDPOPT_BIT;
%ignore IDPOPT_FLT;
%ignore IDPOPT_I64;
%ignore IDPOPT_OK;
%ignore IDPOPT_BADKEY;
%ignore IDPOPT_BADTYPE;
%ignore IDPOPT_BADVALUE;
%ignore set_options_t;
%ignore read_config;
%ignore read_config2;
%ignore read_config_file;
%ignore read_config_file2;
%ignore read_config_string;
%ignore cfgopt_t;
%ignore cfgopt_t__apply;
%ignore cfgopt_t__apply2;
%ignore cfgopt_t__apply3;
%ignore cfgopt_set_t;
%ignore cfgopt_set_vec_t;
%ignore parse_config_value;

%define_Hooks_class(IDP);
%ignore _wrap_addr_in_pycapsule;

%ignore s_preline;
%ignore ca_operation_t;
%ignore _chkarg_cmd;
%ignore ENUM_SIZE;

%ignore asm_t::out_func_header;
%ignore asm_t::out_func_footer;
%ignore asm_t::get_type_name;
%ignore instruc_t;
%ignore IDP_Hooks::dispatch;
%ignore _py_getreg;
%rename (_processor_t) processor_t;
%ignore processor_t::is_funcarg_off;
%ignore processor_t::ensure_processor;
%ignore processor_t::lvar_off;
%ignore processor_t::is_lumina_usable;
%ignore processor_t::get_regfinder();
// The following are queried by the "scripting" processor module support
%ignore processor_t::id;
%ignore processor_t::flag;
%ignore processor_t::flag2;
%ignore processor_t::cnbits;
%ignore processor_t::dnbits;
%ignore processor_t::psnames;
%ignore processor_t::plnames;
%ignore processor_t::assemblers;
%ignore processor_t::_notify;
%ignore processor_t::reg_names;
%ignore processor_t::regs_num;
%ignore processor_t::reg_first_sreg;
%ignore processor_t::reg_last_sreg;
%ignore processor_t::segreg_size;
%ignore processor_t::reg_names;
%ignore processor_t::reg_code_sreg;
%ignore processor_t::reg_data_sreg;
%ignore processor_t::codestart;
%ignore processor_t::retcodes;
%ignore processor_t::instruc_start;
%ignore processor_t::instruc_end;
%ignore processor_t::instruc;
%ignore processor_t::tbyte_size;
%ignore processor_t::real_width;
%ignore processor_t::icode_return;
%ignore processor_t::unused_slot;

%ignore event_listener_t;
%ignore hook_event_listener;
%ignore unhook_event_listener;
%ignore ignore_micro_t;
%ignore modctx_t;
%ignore procmod_t;
%ignore plugmod_t;
%ignore get_hexdsp;
%ignore set_hexdsp;
%ignore remove_event_listener;
%ignore set_module_data;
%ignore clr_module_data;
%ignore get_module_data;
%ignore get_modctx;

// @arnaud
%ignore notify__calc_next_eas;
%ignore notify__custom_ana;
%ignore notify__custom_emu;
%ignore notify__custom_mnem;
%ignore notify__custom_out;
%ignore notify__custom_outop;
%ignore notify__get_autocmt;
%ignore notify__get_dbr_opnum;
%ignore notify__get_operand_string;
%ignore notify__insn_reads_tbit;
%ignore notify__is_basic_block_end;
%ignore notify__is_call_insn;
%ignore notify__is_cond_insn;
%ignore notify__is_indirect_jump;
%ignore notify__is_insn_table_jump;
%ignore notify__is_ret_insn;
%ignore notify__is_sane_insn;
%ignore notify__may_be_func;
%ignore notify__make_code;
// @arnaud ^^^

%template(reg_access_vec_t) qvector<reg_access_t>;

// ph_calcrel
%apply size_t *OUTPUT { size_t *out_consumed };
%apply bytevec_t *vout { bytevec_t *out_relbits };

// ev_cvt64_supval, ev_cvt64_hashval, ev_privrange_changed
%const_pointer_and_size(uchar, data, datlen, bytevec_t, PyBytes_as_bytevec_t, size);
%typemap(argout) (qstring *errbuf)
{
  // %typemap(argout) (qstring *errbuf)
  if ( result < 0 )
  {
    Py_XDECREF($result);
    if ( $1 != nullptr )
      $result = PyUnicode_from_qstring(*$1);
    else
      $result = PyUnicode_FromString("Unknown error");
  }
}

%define %fill_director_method_errbuf(METHOD_NAME)
%typemap(directorout) int METHOD_NAME
{
  // %typemap(directorout) int METHOD_NAME
  if ( PyString_Check(result) )
  {
    if ( errbuf != nullptr )
    {
      PyUnicode_as_qstring(errbuf, result);
    }
    $result = -1;
  }
  else if ( PyLong_Check(result) )
  {
    $result = PyLong_AsLong(result);
  }
  else
  {
    Swig::DirectorTypeMismatchException::raise(
            SWIG_ErrorType(SWIG_TypeError),
            "in output value of type '" "int" "'" " in method '$symname'");
  }
}
%enddef
%fill_director_method_errbuf(ev_cvt64_supval);
%fill_director_method_errbuf(ev_cvt64_hashval);
%fill_director_method_errbuf(ev_privrange_changed);

// @arnaud ditch this once all modules are ported
// temporary:
%ignore out_old_data;
%ignore out_old_specea;

%pywraps_nonnul_argument_prototype(
        static PyObject *AssembleLine(ea_t ea, ea_t cs, ea_t ip, bool use32, const char *nonnul_line),
        const char *nonnul_line);

#ifndef SWIGIMPORTED // let's not modify the wrappers for modules %import'ing us (e.g., typeinf.i, hexrays.i)
%cstring_output_buf_and_size_returning_charptr(
        1,
        char *buf,
        size_t bufsize); // get_idp_name
#endif // SWIGIMPORTED

%cstring_output_qstring_returning_charptr(
        1,
        qstring *out,
        const char *name,
        uint32 disable_mask,
        int demreq); // ev_demangle_name

%include "idp.hpp"
%include "config.hpp"
%include "idacfg.hpp"

#ifndef SWIGIMPORTED // see above
// prevent tinfo_t * check in some functions (e.g., '_wrap_IDP_Hooks_ev_adjust_argloc')
%typemap(check) tinfo_t const* optional_type{ /* suppressed 'tinfo_t *' NULL check */ }
#endif
%inline %{
//<inline(py_idp)>
//</inline(py_idp)>
%}
#ifndef SWIGIMPORTED // see above
%clear const tinfo_t *optional_type;
#endif

%{
//<code(py_idp)>
//</code(py_idp)>
%}

%pythoncode %{
#<pycode(py_idp)>
#</pycode(py_idp)>
%}


//-------------------------------------------------------------------------
//                               IDB_Hooks
//-------------------------------------------------------------------------
%{
#include <enum.hpp>
%}

%define_Hooks_class(IDB);

%inline %{
//<inline(py_idp_idbhooks)>
//</inline(py_idp_idbhooks)>
%}

%{
//<code(py_idp_idbhooks)>
//</code(py_idp_idbhooks)>
%}

%pythoncode %{
#<pycode(py_idp_idbhooks)>
#</pycode(py_idp_idbhooks)>
%}


//-------------------------------------------------------------------------
//                             notify_when()
//-------------------------------------------------------------------------
%{
//<code(py_idp_notify_when)>
//</code(py_idp_notify_when)>
%}

%pythoncode %{
#<pycode(py_idp_notify_when)>
#</pycode(py_idp_notify_when)>
%}

