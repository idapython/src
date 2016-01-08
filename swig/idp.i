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
%ignore read_kernel_config_file;
%ignore split_path_envvar;
%ignore get_user_idadirs;
%ignore find_cfg_files;
%ignore cfgopt_t;
%ignore cfgopt_t__apply;
%ignore parse_config_value;
%ignore get_idptype_and_data;


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
%ignore IDB_Callback;
%ignore IDP_Callback;
%ignore _py_getreg;
%ignore free_processor_module;
%ignore cfg_compiler_changed;

%ignore gen_idb_event;
%ignore print_spec_entry;

%include "idp.hpp"

%extend areacb_t {
  areacb_type_t get_type()
  {
    areacb_type_t t = AREACB_TYPE_UNKNOWN;
    if ( $self == &funcs )
      t = AREACB_TYPE_FUNC;
    else if ( $self == &segs )
      t = AREACB_TYPE_SEGMENT;
    else if ( $self == &hidden_areas )
      t = AREACB_TYPE_HIDDEN_AREA;
    return t;
  }
}

%ignore IDP_Hooks::bool_to_cmdsize;
%ignore IDP_Hooks::bool_to_2or0;
%ignore IDP_Hooks::cm_t_to_int;
%ignore IDP_Hooks::handle_custom_mnem_output;
%ignore IDP_Hooks::handle_assemble_output;

%inline %{
//<inline(py_idp)>
//</inline(py_idp)>
%}

%{
//<code(py_idp)>
//</code(py_idp)>
%}
