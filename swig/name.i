%cstring_output_maxstr_none(char *buf, int bufsize);

%cstring_bounded_output(char *dstname, MAXSTR);
%cstring_bounded_output(char *buf, MAXSTR);

// This is for get_name_value's output value
%apply unsigned long *OUTPUT { uval_t *value };

// FIXME: These should be fixed
%ignore get_struct_operand;
%ignore set_debug_names;
%ignore nameVa;

// Unexported & kernel-only
%ignore addDummyName;
%ignore convert_debug_names_to_normal;
%ignore convert_name_formats;
%ignore showhide_name;
%ignore clear_lname_bit;
%ignore fix_new_name;
%ignore rename;
%ignore move_names;
%ignore is_noret_name;
%ignore is_exit_name;
%ignore dummy_name_ea;
%ignore calc_gtn_flags;
%ignore detect_compiler_using_demangler;
%ignore getname_info_t;
%ignore get_ea_name;
%rename (get_ea_name) py_get_ea_name;

%ignore make_visible_name2;


// Deprecated functions, w/ duplicate names.
// Some are simply aliased (see py_name.py)
%ignore get_debug_name(ea_t *, debug_name_how_t, char *, size_t);
%ignore append_struct_fields(int, const tid_t *, int, flags_t, char *, char *, adiff_t *, adiff_t, bool);


// Duplicate names, in-out qstring w/ existing
// qstring-returning alternatives.
%ignore get_visible_name(qstring *, ea_t, int);
%ignore get_short_name(qstring *, ea_t, int);
%ignore get_long_name(qstring *, ea_t, int);

// get_true_name & get_colored_name have prototypes such that,
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

%inline %{
inline qstring py_## FNAME(ea_t ea) { return FNAME(ea); }
%}
%enddef

%restrict_ambiguous_name_function(get_true_name);
%restrict_ambiguous_name_function(get_colored_name);


%ignore get_debug_names;
%rename (get_debug_names) py_get_debug_names;

%{
//<code(py_name)>
//</code(py_name)>
%}

%include "name.hpp"

%inline %{
//<inline(py_name)>
//------------------------------------------------------------------------
PyObject *py_get_debug_names(ea_t ea1, ea_t ea2)
{
  // Get debug names
  ea_name_vec_t names;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  Py_BEGIN_ALLOW_THREADS;
  get_debug_names(ea1, ea2, names);
  Py_END_ALLOW_THREADS;
  PyObject *dict = Py_BuildValue("{}");
  if (dict != NULL)
  {
    for (ea_name_vec_t::iterator it=names.begin();it!=names.end();++it)
    {
      PyDict_SetItem(dict,
                     Py_BuildValue(PY_FMT64, it->ea),
                     PyString_FromString(it->name.c_str()));
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
//------------------------------------------------------------------------
//</inline(py_name)>
%}

%pythoncode %{
#<pycode(py_name)>

class NearestName:
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

extract_name = extract_name2

#</pycode(py_name)>
%}

