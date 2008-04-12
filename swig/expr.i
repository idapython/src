%ignore extfun_t;
%ignore funcset_t;
%ignore IDCFuncs;
%ignore set_idc_func;
%ignore VarLong;
%ignore VarNum;
%ignore VarString;
%ignore VarFloat;
%ignore VarFree;
%ignore calcexpr_long;
%ignore Run;
%ignore ExecuteLine;
%ignore ExecuteFile;
%ignore set_idc_func_body;
%ignore get_idc_func_body;
%ignore idc_stacksize;
%ignore idc_calldepth;
%ignore expr_printf;
%ignore expr_sprintf;
%ignore expr_printfer;
%ignore idaapi init_idc;
%ignore idaapi term_idc;
%ignore del_idc_userfuncs;
%ignore find_builtin_idc_func;
%ignore idc_lx;


%cstring_output_maxstr_none(char *errbuf, size_t errbufsize);
%include "expr.hpp"


