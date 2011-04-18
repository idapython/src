%cstring_output_maxstr_none(char *buf, int bufsize);

%cstring_bounded_output(char *dstname, MAXSTR);
%cstring_bounded_output(char *buf, MAXSTR);

// This is for get_name_value's output value
%apply unsigned long *OUTPUT { uval_t *value };

// FIXME: These should be fixed
%ignore append_struct_fields;
%ignore get_struct_operand;
%ignore set_debug_names;
%ignore get_debug_name;
%ignore get_debug_names;
%ignore nameVa;

// Unexported & kernel-only
%ignore get_short_name;
%ignore get_long_name;
%ignore get_colored_short_name;
%ignore get_colored_long_name;
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

%rename (get_debug_names) py_get_debug_names;
%inline %{
PyObject *py_get_debug_names(ea_t ea1, ea_t ea2)
{
  // Get debug names
  ea_name_vec_t names;
  get_debug_names(ea1, ea2, names);
  PyObject *dict = Py_BuildValue("{}");
  if (dict == NULL)
    return NULL;

  for (ea_name_vec_t::iterator it=names.begin();it!=names.end();++it)
  {
    PyDict_SetItem(dict,
      Py_BuildValue(PY_FMT64, it->ea),
      PyString_FromString(it->name.c_str()));
  }
  return dict;
}
%}

%pythoncode %{

import bisect

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

%}
%include "name.hpp"
