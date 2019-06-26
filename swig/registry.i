%{
#include <registry.hpp>
%}
%ignore reg_bin_op;
%ignore reg_str_get;
%ignore reg_str_set;
%ignore reg_int_op;
%ignore _RVN_;
%ignore REG_VAL_NAME;
%ignore REG_BOOL_FUNC;
%ignore REG_INT_FUNC;
%ignore MAX_HISTORY_FILES_DEF;
%ignore regkey_history;
%ignore max_history_files;
%ignore regget_history;
%ignore reg_update_history;
%ignore reg_history_size_truncate;

%ignore reg_read_string;
%rename (reg_read_string) py_reg_read_string;

%ignore reg_data_type;
%rename (reg_data_type) py_reg_data_type;

%ignore reg_read_binary;
%rename (reg_read_binary) py_reg_read_binary;
%ignore reg_write_binary;
%rename (reg_write_binary) py_reg_write_binary;

%ignore reg_read_binary_part;

/* inline bool reg_subkey_subkeys(qstrvec_t *out, const char *name) */
%ignore reg_subkey_subkeys;
%rename (reg_subkey_subkeys) py_reg_subkey_subkeys;
%ignore reg_subkey_values;
%rename (reg_subkey_values) py_reg_subkey_values;
%ignore reg_subkey_children;

%apply qstrvec_t *out { qstrvec_t *list };

%{
//<code(py_registry)>
//</code(py_registry)>
%}

%inline %{
//<inline(py_registry)>
//</inline(py_registry)>
%}

//<typemaps(registry)>
//</typemaps(registry)>

%include "registry.hpp"
