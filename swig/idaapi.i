%module(docstring="IDA Pro Plugin SDK API wrapper",directors="1") idaapi
// Suppress 'previous definition of XX' warnings
#pragma SWIG nowarn=302
// Enable automatic docstring generation
%feature(autodoc);
%{
#include <Python.h>
#define USE_DANGEROUS_FUNCTIONS 1
#ifdef HAVE_SSIZE_T
#define _SSIZE_T_DEFINED 1
#endif
#include "ida.hpp"
#include "idp.hpp"
#include "allins.hpp"
#include "auto.hpp"
#include "bytes.hpp"
#include "dbg.hpp"
#include "diskio.hpp"
#include "entry.hpp"
#include "enum.hpp"
#include "expr.hpp"
#include "frame.hpp"
#include "fixup.hpp"
#include "funcs.hpp"
#include "gdl.hpp"
#include "idd.hpp"
#include "ints.hpp"
#include "kernwin.hpp"
#include "lines.hpp"
#include "loader.hpp"
#include "moves.hpp"
#include "netnode.hpp"
#include "nalt.hpp"
#include "name.hpp"
#include "offset.hpp"
#include "queue.hpp"
#include "search.hpp"
#include "srarea.hpp"
#include "strlist.hpp"
#include "struct.hpp"
#include "typeinf.hpp"
#include "ua.hpp"
#include "xref.hpp"
%}

#ifdef __EA64__
%constant ea_t BADADDR = 0xFFFFFFFFFFFFFFFF;
%constant sel_t BADSEL = 0xFFFFFFFFFFFFFFFF;
%constant nodeidx_t BADNODE = 0xFFFFFFFFFFFFFFFF;
#else
%constant ea_t BADADDR = 0xFFFFFFFF;
%constant sel_t BADSEL = 0xFFFFFFFF;
%constant nodeidx_t BADNODE = 0xFFFFFFFF;
#endif

// Help SWIG to figure out the ulonglong type
#ifdef SWIGWIN
typedef unsigned __int64 ulonglong;
typedef          __int64 longlong;
#else
typedef unsigned long long ulonglong;
typedef          long long longlong;
#endif

%include "typemaps.i"

%include "cstring.i"
%include "carrays.i"
%include "cpointer.i"

%include "typeconv.i"

%include "pro.h"

// Do not move this. We need to override the define from pro.h
#define CASSERT(type)

// Convert all of these
%cstring_output_maxstr_none(char *buf, size_t bufsize);

%array_class(uchar, uchar_array);
%array_class(tid_t, tid_array);
%array_class(ea_t, ea_array);
%array_class(sel_t, sel_array);
%array_class(uval_t, uval_array);
%pointer_class(int, int_pointer);
%pointer_class(ea_t, ea_pointer);
%pointer_class(sval_t, sval_pointer);
%pointer_class(sel_t, sel_pointer);

%include "ida.i"
%include "idd.i"
%include "idp.i"
%include "netnode.i"
%include "nalt.i"

%include "allins.i"
%include "area.i"
%include "auto.i"
%include "bytes.i"
%include "dbg.i"
%include "diskio.i"
%include "entry.i"
%include "enum.i"
%include "expr.i"
%include "fixup.i"
%include "frame.i"
%include "funcs.i"

%inline {
/* Small wrapper to get the inf structure */
idainfo *get_inf_structure(void)
{
	return &inf;
}
}

%include "gdl.i"
%include "ints.i"
%include "kernwin.i"
%include "lines.i"
%include "loader.i"
%include "moves.i"
%include "name.i"
%include "offset.i"
%include "queue.i"
%include "search.i"
%include "segment.i"
%include "srarea.i"
%include "strlist.i"
%include "struct.i"
%include "typeinf.i"
%include "ua.i"
%include "xref.i"

%inline {
	void enable_extlang_python(bool enable);
#if IDA_SDK_VERSION >= 540
	void enable_python_cli(bool enable);
#endif
}
