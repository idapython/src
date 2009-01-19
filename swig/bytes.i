// Make put_many_bytes and patch_many_bytes work
%apply (char *STRING, int LENGTH) { (const void *buf, size_t size) };

// Make get_any_cmt() work
%apply unsigned char *OUTPUT { color_t *cmttype };

// For get_enum_id()
%apply unsigned char *OUTPUT { uchar *serial };

// Unexported and kernel-only declarations
%ignore FlagsEnable;
%ignore FlagsDisable;
%ignore testf_t;
%ignore nextthat;
%ignore prevthat;
%ignore adjust_visea;
%ignore prev_visea;
%ignore next_visea;
%ignore is_first_visea;
%ignore is_last_visea;
%ignore is_visible_finally;
%ignore invalidate_visea_cache;
%ignore fluFlags;
%ignore setFlbits;
%ignore clrFlbits;
%ignore get_8bit;
%ignore get_ascii_char;
%ignore del_typeinfo;
%ignore del_operand_typeinfo;
%ignore doCode;
%ignore get_repeatable_cmt;
%ignore get_any_indented_cmt;
%ignore del_code_comments;
%ignore doFlow;
%ignore noFlow;
%ignore doRef;
%ignore noRef;
%ignore doExtra;
%ignore noExtra;
%ignore coagulate;
%ignore coagulate_dref;
%ignore get_item_head;
%ignore init_hidden_areas;
%ignore save_hidden_areas;
%ignore term_hidden_areas;
%ignore check_move_args;
%ignore movechunk;
%ignore lock_dbgmem_config;
%ignore unlock_dbgmem_config;
%ignore set_op_type_no_event;
%ignore shuffle_tribytes;
%ignore set_enum_id;
%ignore validate_tofs;
%ignore ida_vpagesize;
%ignore ida_vpages;
%ignore ida_npagesize;
%ignore ida_npages;
%ignore fpnum_digits;
%ignore fpnum_length;
%ignore FlagsInit;
%ignore FlagsTerm;
%ignore FlagsReset;

// TODO: These could be fixed if someone needs them.
%ignore get_many_bytes;
%ignore set_dbgmem_source;
%ignore invalidate_dbgmem_config;
%ignore invalidate_dbgmem_contents;

%include "bytes.hpp"

%clear(void *buf, ssize_t size);

%clear(const void *buf, size_t size);
%clear(void *buf, ssize_t size);
%clear(typeinfo_t *);
 
