%{
#include <loader.hpp>
#include <diskio.hpp>
%}

%{
#include <Python.h>

#ifdef HAVE_SSIZE_T
#define _SSIZE_T_DEFINED 1
#endif

//<code(py_idaapi)>
//</code(py_idaapi)>
%}

%ignore parse_command_line3;
%rename (parse_command_line3) py_parse_command_line;

%constant ea_t BADADDR = ea_t(-1);
%constant ea32_t BADADDR32 = ea32_t(-1ULL);
%constant ea64_t BADADDR64 = ea64_t(-1ULL);
%constant sel_t BADSEL = sel_t(-1);
%constant size_t SIZE_MAX = size_t(-1);
/* %constant nodeidx_t BADNODE = nodeidx_t(-1); */

%include "typemaps.i"

%include "cstring.i"
%include "carrays.i"
%include "cpointer.i"

%pythoncode %{
#<pycode(py_idaapi)>
#</pycode(py_idaapi)>
%}


%inline %{
//<inline(py_idaapi)>
//</inline(py_idaapi)>
%}

%pythoncode %{
import types
uses_swig_builtins = isinstance(get_inf_structure, types.BuiltinFunctionType)
%}

//-------------------------------------------------------------------------
%inline %{
//<inline(py_idaapi_loader_input)>
//</inline(py_idaapi_loader_input)>
%}
