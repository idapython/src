%{
#include <idp.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <auto.hpp>
#include <fixup.hpp>
%}
// Ignore the following symbols
%ignore WorkReg;
%ignore AbstractRegister;
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
%ignore read_user_config_file;
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

%ignore asm_t::checkarg_dispatch;
%ignore asm_t::func_header;
%ignore asm_t::func_footer;
%ignore asm_t::get_type_name;
%ignore instruc_t;
%ignore processor_t;
%ignore ph;
%ignore IDP_Callback;
%ignore _py_getreg;

%nonnul_argument_prototype(
        static PyObject *AssembleLine(ea_t ea, ea_t cs, ea_t ip, bool use32, const char *nonnul_line),
        const char *nonnul_line);

%include "idp.hpp"

%inline %{
//<inline(py_idp)>
//</inline(py_idp)>
%}

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
