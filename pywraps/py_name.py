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
        self._addrs = list(ea_names.keys())
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
        return (self._get_item(index) for index in range(0, len(self._addrs)))


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
