// Kernel only & unexported symbols
%ignore enums;
%ignore init_enums;
%ignore save_enums;
%ignore term_enums;
%ignore set_enum_flag;
%ignore sync_from_enum;;
%ignore del_all_consts;
%ignore get_selected_enum;
%ignore add_selected_enum;
%ignore unmark_selected_enums;
%ignore is_good_bmask;
%ignore get_bmask_enum;
%ignore ENUM_REVERSE;
%ignore ENUM_SELMEMS;
%ignore ENUM_QTY_IDX;
%ignore ENUM_FLG_IDX;
%ignore ENUM_FLAGS;
%ignore ENUM_FLAGS_IS_BF;
%ignore ENUM_FLAGS_HIDDEN;
%ignore ENUM_MASKS;
%ignore ENUM_MEMBERS;
%ignore CONST_ENUM;
%ignore CONST_VALUE;
%ignore CONST_BMASK;
%ignore CONST_SERIAL;
%ignore CONST_SERIALS;

// FIXME: Check uval_t declarations

%include "enum.hpp"
