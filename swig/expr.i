%ignore extfun_t;
%ignore funcset_t;
%ignore extlang_t;
%ignore extlang;
%ignore register_extlang;
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
%ignore del_idc_userdefs;
%ignore find_builtin_idc_func;
%ignore idc_lx;
%ignore idc_vars;

%cstring_output_maxstr_none(char *errbuf, size_t errbufsize);

/* Compile* functions return false when error so the return  */
/* value must be negated for the error string to be returned */
%rename (CompileEx) CompileEx_wrap;
%inline %{
bool CompileEx_wrap(const char *file, bool del_macros,
                    char *errbuf, size_t errbufsize)
{
	return !CompileEx(file, del_macros, errbuf, errbufsize);
}
%}

%rename (Compile) Compile_wrap;
%inline %{
bool Compile_wrap(const char *file, char *errbuf, size_t errbufsize)
{
	return !Compile(file, errbuf, errbufsize);
}
%}

%rename (calcexpr) calcexpr_wrap;
%inline %{
bool calcexpr_wrap(ea_t where,const char *line, idc_value_t *rv, char *errbuf, size_t errbufsize)
{
 	return !calcexpr(where, line, rv, errbuf, errbufsize);
}
%}

%rename (calc_idc_expr) calc_idc_expr_wrap;
%inline %{
bool calc_idc_expr_wrap(ea_t where,const char *line, idc_value_t *rv, char *errbuf, size_t errbufsize)
{
 	return !calc_idc_expr(where, line, rv, errbuf, errbufsize);
}
%}
        
%ignore CompileLine(const char *line, char *errbuf, size_t errbufsize, uval_t (idaapi*_getname)(const char *name)=NULL);

%rename (CompileLine) CompileLine_wrap;
%inline %{
bool CompileLine_wrap(const char *line, char *errbuf, size_t errbufsize)
{
	return !CompileLine(line, errbuf, errbufsize);
}
%}

%include "expr.hpp"

