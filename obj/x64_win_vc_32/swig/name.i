%module(docstring="IDA Plugin SDK API wrapper: name",directors="1",threads="1") ida_name
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_NAME
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_NAME
  #define HAS_DEP_ON_INTERFACE_NAME
#endif
%include "header.i"
%include "cstring.i"
%cstring_bounded_output(char *dstname, MAXSTR);
%cstring_bounded_output(char *buf, MAXSTR);

%apply unsigned long *OUTPUT { uval_t *value }; // get_name_value
%apply unsigned long *INPUT { ea_t *ea_ptr }; // get_debug_name

// FIXME: These should be fixed
%ignore get_struct_operand;
%ignore set_debug_names;

// Unexported & kernel-only
%ignore is_exit_name;
%ignore dummy_name_ea;
%ignore calc_gtn_flags;
%ignore detect_compiler_using_demangler;
%ignore getname_info_t;
%ignore get_ea_name;
%rename (get_ea_name) py_get_ea_name;

// Duplicate names, in-out qstring w/ existing
// qstring-returning alternatives.
%ignore get_visible_name(qstring *, ea_t, int);
%ignore get_short_name(qstring *, ea_t, int);
%ignore get_long_name(qstring *, ea_t, int);
%ignore get_colored_short_name(qstring *, ea_t, int);
%ignore get_colored_long_name(qstring *, ea_t, int);
%ignore get_demangled_name(qstring *, ea_t, int32, int, int);
%ignore get_colored_demangled_name(qstring *, ea_t, int32, int, int);

%uncomparable_elements_qvector(ea_name_t, ea_name_vec_t);

// get_name & get_colored_name have prototypes such that,
// once converted to IDAPython, would be problematic because it'd
// be impossible for SWiG to tell apart the (ea_t, ea_t) version
// from the (ea_t, int) one.
// Therefore, we cannot allow access to the (ea_t, int) one (and
// we keep the other for bw-compat reasons). If users want to use
// 'flags' versions, they can still rely on get_ea_name().
%define %restrict_ambiguous_name_function(FNAME)
%ignore FNAME(qstring *, ea_t, int);
%ignore FNAME(ea_t, int);
%rename (FNAME) py_ ## FNAME;

%ignore demangle_name(const char *, uint32, demreq_type_t);

%inline %{
inline qstring py_## FNAME(ea_t ea) { return FNAME(ea); }
%}
%enddef

%restrict_ambiguous_name_function(get_name);
%restrict_ambiguous_name_function(get_colored_name);

%ignore validate_name;
%rename (validate_name) py_validate_name;

%{
//<code(py_name)>
//</code(py_name)>
%}

%include "name.hpp"

%inline %{
//<inline(py_name)>
//------------------------------------------------------------------------
PyObject *get_debug_names(ea_t ea1, ea_t ea2)
{
  // Get debug names
  ea_name_vec_t names;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  Py_BEGIN_ALLOW_THREADS;
  get_debug_names(&names, ea1, ea2);
  Py_END_ALLOW_THREADS;
  PyObject *dict = Py_BuildValue("{}");
  if ( dict != NULL )
  {
    for ( ea_name_vec_t::iterator it=names.begin(); it != names.end(); ++it )
    {
      PyDict_SetItem(dict,
                     Py_BuildValue(PY_BV_EA, bvea_t(it->ea)),
                     IDAPyStr_FromUTF8(it->name.c_str()));
    }
  }
  return dict;
}

//-------------------------------------------------------------------------
inline qstring py_get_ea_name(ea_t ea, int gtn_flags=0)
{
  qstring out;
  get_ea_name(&out, ea, gtn_flags);
  return out;
}

//-------------------------------------------------------------------------
PyObject *py_validate_name(const char *name, nametype_t type, int flags=0)
{
  qstring qname(name);
  if ( validate_name(&qname, type, flags) )
    return IDAPyStr_FromUTF8AndSize(qname.c_str(), qname.length());
  else
    Py_RETURN_NONE;
}
//</inline(py_name)>
%}

%pythoncode %{
#<pycode(py_name)>
import _ida_idaapi
import _ida_funcs
import bisect


class NearestName(object):
    """
    Utility class to help find the nearest name in a given ea/name dictionary
    """
    def __init__(self, ea_names):
        self.update(ea_names)


    def update(self, ea_names):
        """Updates the ea/names map"""
        self._names = ea_names
        self._addrs = ea_names.keys()
        self._addrs.sort()


    def find(self, ea):
        """
        Returns a tupple (ea, name, pos) that is the nearest to the passed ea
        If no name is matched then None is returned
        """
        pos = bisect.bisect_left(self._addrs, ea)
        # no match
        if pos >= len(self._addrs):
            return None
        # exact match?
        if self._addrs[pos] != ea:
            pos -= 1 # go to previous element
        if pos < 0:
            return None
        return self[pos]


    def _get_item(self, index):
        ea = self._addrs[index]
        return (ea, self._names[ea], index)


    def __iter__(self):
        return (self._get_item(index) for index in xrange(0, len(self._addrs)))


    def __getitem__(self, index):
        """Returns the tupple (ea, name, index)"""
        if index > len(self._addrs):
            raise StopIteration
        return self._get_item(index)

def calc_gtn_flags(fromaddr, ea):
    """
    Calculate flags for get_ea_name() function

    @param fromaddr: the referring address. May be BADADDR.
    @param ea: linear address

    @return: flags
    """
    gtn_flags = 0
    if fromaddr != _ida_idaapi.BADADDR:
        pfn = _ida_funcs.get_func(fromaddr)
        if _ida_funcs.func_contains(pfn, ea):
            gtn_flags = GN_LOCAL
    return gtn_flags

#</pycode(py_name)>
%}

%pythoncode %{
if _BC695:
    GN_INSNLOC=0
    @bc695redef
    def demangle_name(name, mask, demreq=DQT_FULL): # make flag optional, so demangle_name & demangle_name2 can use it
        return _ida_name.demangle_name(name, mask, demreq)
    demangle_name2=demangle_name
    def do_name_anyway(ea, name, maxlen=0):
        return force_name(ea, name)
    extract_name2=extract_name
    get_debug_name2=get_debug_name
    def get_true_name(ea0, ea1=None):
        if ea1 is None:
            ea = ea0
        else:
            ea = ea1
        return get_name(ea)
    is_ident_char=is_ident_cp
    is_visible_char=is_visible_cp
    def make_visible_name(name, sz=0):
        if sz > 0:
            name = name[0:sz]
        return _ida_name.validate_name(name, VNT_VISIBLE)
    def validate_name2(name, sz=0):
        if sz > 0:
            name = name[0:sz]
        return _ida_name.validate_name(name, VNT_IDENT)
    def validate_name3(name):
        return _ida_name.validate_name(name, VNT_IDENT)
    isident=is_ident
    @bc695redef
    def get_name(*args):
        if len(args) == 2:
            if args[0] != _ida_idaapi.BADADDR:
                print("Compatibility get_name(from, ea) was called with non-BADADDR first argument (0x%08x). There is no equivalent in the new API, and the results might be erroneous." % args[0]);
            return _ida_name.get_name(args[1])
        else:
            return _ida_name.get_name(*args)

%}