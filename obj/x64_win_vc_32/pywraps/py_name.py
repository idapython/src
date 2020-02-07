from __future__ import print_function

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

#<pycode_BC695(py_name)>
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
#</pycode_BC695(py_name)>
