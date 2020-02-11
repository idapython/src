%{
#include <idp.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <auto.hpp>
#include <fixup.hpp>
#include <tryblks.hpp>
%}
// Ignore the following symbols
%ignore rginfo;
%ignore insn_t::get_canon_mnem;
%ignore insn_t::get_canon_feature;
%ignore insn_t::is_canon_insn;
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
%ignore read_config_file;
%ignore read_config_string;
%ignore cfgopt_t;
%ignore cfgopt_t__apply;
%ignore parse_config_value;

%ignore s_preline;
%ignore ca_operation_t;
%ignore _chkarg_cmd;
%ignore ENUM_SIZE;

%ignore asm_t::out_func_header;
%ignore asm_t::out_func_footer;
%ignore asm_t::get_type_name;
%ignore instruc_t;
%ignore processor_t;
%ignore ph;
%ignore IDP_Callback;
%ignore _py_getreg;

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

// @arnaud ditch this once all modules are ported
// temporary:
%ignore out_old_data;
%ignore out_old_specea;

%nonnul_argument_prototype(
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

%ignore IDB_Callback;

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

