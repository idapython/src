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

//%feature("compactdefaultargs") CompileLine;

%ignore CompileLine(const char *line, char *errbuf, size_t errbufsize, uval_t (idaapi*_getname)(const char *name)=NULL);

%rename (CompileLine) CompileLine_wrap;
%inline %{
bool CompileLine_wrap(const char *line, char *errbuf, size_t errbufsize)
{
	return !CompileLine(line, errbuf, errbufsize);
}
%}

%include "expr.hpp"

