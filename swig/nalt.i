%{
#include <nalt.hpp>
#include <name.hpp>
#include <expr.hpp>
#include <loader.hpp>
#include "../../../pywraps.hpp"
%}

%ignore get_import_module_name;
%rename (get_import_module_name) py_get_import_module_name;
%ignore enum_import_names;
%rename (enum_import_names) py_enum_import_names;

%typemap(check) (const char* text, size_t size) {
  size_t len = $1 != nullptr ? qstrlen($1) : 0;
  if ( $2 > len )
    $2 = len;
}

%ignore calc_nodeidx;

%ignore get_wide_value;
%ignore set_wide_value;
%ignore del_wide_value;

%ignore xrefpos_t;
%ignore get_xrefpos;
%ignore set_xrefpos;
%ignore del_xrefpos;

%ignore set_aflags0;
%ignore get_aflags0;
%ignore del_aflags0;

%ignore get_linnum0;
%ignore set_linnum0;
%ignore del_linnum0;

%ignore get_enum_id0;
%ignore set_enum_id0;
%ignore del_enum_id0;
%ignore get_enum_id1;
%ignore set_enum_id1;
%ignore del_enum_id1;

%ignore set_ind_purged;

%ignore _get_item_color;
%ignore _set_item_color;
%ignore _del_item_color;

%ignore get_nalt_cmt;
%ignore set_nalt_cmt;
%ignore del_nalt_cmt;
%ignore get_nalt_rptcmt;
%ignore set_nalt_rptcmt;
%ignore del_nalt_rptcmt;
%ignore get_manual_insn0;
%ignore set_manual_insn0;
%ignore del_manual_insn0;
%ignore get_graph_groups0;
%ignore set_graph_groups0;
%ignore del_graph_groups0;

%ignore jumptable_info_t;
%ignore del_jumptable_info;
%ignore set_jumptable_info;
%ignore get_jumptable_info;

%ignore custom_refinfo_handler_t;
%ignore custom_refinfo_handlers_t;
%ignore register_custom_refinfo;
%ignore unregister_custom_refinfo;
%ignore get_custom_refinfo_handler;
%ignore refinfo_desc_t;
%ignore get_refinfo_descs;

%ignore printop_t::unused;

%ignore write_struc_path;
%ignore read_struc_path;
%ignore del_struc_path;
%ignore get_stroff0;
%ignore set_stroff0;
%ignore del_stroff0;
%ignore get_stroff1;
%ignore set_stroff1;
%ignore del_stroff1;

%ignore get__segtrans;
%ignore set__segtrans;
%ignore del__segtrans;

%ignore validate_idb_names;
%rename (validate_idb_names) validate_idb_names2;

%template (custom_data_type_ids_fids_array) wrapped_array_t<int16,UA_MAXOP>;

%extend custom_data_type_ids_t {
  wrapped_array_t<int16,UA_MAXOP> __getFids() {
    return wrapped_array_t<int16,UA_MAXOP>($self->fids);
  }

  %pythoncode {
    fids = property(__getFids)
  }
}

%template (strpath_ids_array) wrapped_array_t<tid_t,32>;

%extend strpath_t {
  wrapped_array_t<tid_t,32> __getIds() {
    return wrapped_array_t<tid_t,32>($self->ids);
  }

  %pythoncode {
    ids = property(__getIds)
  }
}

%extend printop_t {
  %pythoncode {
    is_ti_valid = property(is_ti_initialized, set_ti_initialized)
  }
}

%ignore switch_info_t::version;

%apply uchar { op_dtype_t regdtype };

%extend switch_info_t
{
  void assign(const switch_info_t &other) { *($self) = other; }
  ea_t _get_values_lowcase() const { return $self->values; }
  void _set_values_lowcase(ea_t values) { $self->values = values; }

  %pythoncode {
    values = property(_get_values_lowcase, _set_values_lowcase)
    lowcase = property(_get_values_lowcase, _set_values_lowcase)
  }
}

%include "nalt.hpp"

%{
//<code(py_nalt)>
//</code(py_nalt)>
%}

%inline %{
//<inline(py_nalt)>
//</inline(py_nalt)>
%}

%pythoncode %{
#<pycode(py_nalt)>
#</pycode(py_nalt)>
%}
