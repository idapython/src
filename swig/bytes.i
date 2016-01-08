// Make get_any_cmt() work
%apply unsigned char *OUTPUT { color_t *cmttype };

// For get_enum_id()
%apply unsigned char *OUTPUT { uchar *serial };

// get_[first|last]_serial_enum_member() won't take serials as input; it'll be present as output
%apply unsigned char *OUTPUT { uchar *out_serial };
// get_[next|prev]_serial_enum_member() take serials as input, and have the result present as output
%apply unsigned char *INOUT { uchar *in_out_serial };

// Unexported and kernel-only declarations
%ignore FlagsEnable;
%ignore FlagsDisable;
%ignore testf_t;
%ignore nextthat;
%ignore prevthat;
%ignore adjust_visea;
%ignore prev_visea;
%ignore next_visea;
%ignore visit_patched_bytes;
%ignore is_first_visea;
%ignore is_last_visea;
%ignore is_visible_finally;
%ignore invalidate_visea_cache;
%ignore fluFlags;
%ignore setFlbits;
%ignore clrFlbits;
%ignore get_8bit;
%ignore get_ascii_char;
%ignore del_opinfo;
%ignore del_one_opinfo;
%ignore doCode;
%ignore get_repeatable_cmt;
%ignore get_any_indented_cmt;
%ignore del_code_comments;
%ignore doFlow;
%ignore noFlow;
%ignore doRef;
%ignore noRef;
%ignore coagulate;
%ignore coagulate_dref;
%ignore init_hidden_areas;
%ignore save_hidden_areas;
%ignore term_hidden_areas;
%ignore check_move_args;
%ignore movechunk;
%ignore lock_dbgmem_config;
%ignore unlock_dbgmem_config;
%ignore set_op_type_no_event;
%ignore shuffle_tribytes;
%ignore set_stroff_path;
%ignore del_stroff_path;
%ignore set_enum_id;
%ignore del_enum_id;
%ignore enum_encode;
%ignore enum_decode;
%ignore mark_dirty_tof;
%ignore validate_tofs;
%ignore set_flags_nomark;
%ignore set_flbits_nomark;
%ignore clr_flbits_nomark;
%ignore ida_vpagesize;
%ignore ida_vpages;
%ignore ida_npagesize;
%ignore ida_npages;
%ignore max_cache_count;

%ignore fpnum_digits;
%ignore fpnum_length;
%ignore FlagsInit;
%ignore FlagsTerm;
%ignore FlagsReset;
%ignore init_flags;
%ignore term_flags;
%ignore reset_flags;
%ignore flush_flags;
%ignore get_flags_linput;
%ignore data_type_t;
%ignore data_format_t;
%ignore get_custom_data_type;
%ignore get_custom_data_format;
%ignore unregister_custom_data_format;
%ignore register_custom_data_format;
%ignore unregister_custom_data_type;
%ignore register_custom_data_type;
%ignore get_many_bytes;
%ignore get_ascii_contents;
%ignore get_ascii_contents2;
%ignore get_hex_string;

// TODO: This could be fixed (if needed)
%ignore set_dbgmem_source;

%include "bytes.hpp"

%clear(void *buf, ssize_t size);

%clear(const void *buf, size_t size);
%clear(void *buf, ssize_t size);
%clear(opinfo_t *);

%rename (visit_patched_bytes) py_visit_patched_bytes;
%rename (nextthat) py_nextthat;
%rename (prevthat) py_prevthat;
%rename (get_custom_data_type) py_get_custom_data_type;
%rename (get_custom_data_format) py_get_custom_data_format;
%rename (unregister_custom_data_format) py_unregister_custom_data_format;
%rename (register_custom_data_format) py_register_custom_data_format;
%rename (unregister_custom_data_type) py_unregister_custom_data_type;
%rename (register_custom_data_type) py_register_custom_data_type;
%rename (get_many_bytes) py_get_many_bytes;
%rename (get_ascii_contents) py_get_ascii_contents;
%rename (get_ascii_contents2) py_get_ascii_contents2;
%{
//<code(py_bytes)>
//</code(py_bytes)>
%}

%inline %{
//<inline(py_bytes)>
//</inline(py_bytes)>
%}

%pythoncode %{
#<pycode(py_bytes)>
#</pycode(py_bytes)>
%}
