
#<pycode(py_pro)>
import ida_idaapi

longlongvec_t = int64vec_t
ulonglongvec_t = uint64vec_t

if ida_idaapi.__EA64__:
    svalvec_t = int64vec_t
    uvalvec_t = uint64vec_t
else:
    svalvec_t = intvec_t
    uvalvec_t = uintvec_t
eavec_t = uvalvec_t

ida_idaapi._listify_types(
        intvec_t,
        uintvec_t,
        int64vec_t,
        uint64vec_t,
        boolvec_t,
        strvec_t)

# -----------------------------------------------------------------------
# qstrvec_t clinked object
class _qstrvec_t(ida_idaapi.py_clinked_object_t):
    """
    WARNING: It is very unlikely an IDAPython user should ever, ever
    have to use this type. It should only be used for IDAPython internals.

    For example, in py_askusingform.py, we ctypes-expose to the IDA
    kernel & UI a qstrvec instance, in case a DropdownListControl is
    constructed.
    That's because that's what ask_form expects, and we have no
    choice but to make a DropdownListControl hold a qstrvec_t.
    This is, afaict, the only situation where a Python
    _qstrvec_t is required.
    """

    def __init__(self, items=None):
        ida_idaapi.py_clinked_object_t.__init__(self)
        # Populate the list if needed
        if items:
            self.from_list(items)

    def _create_clink(self):
        return _ida_pro.qstrvec_t_create()

    def _del_clink(self, lnk):
        return _ida_pro.qstrvec_t_destroy(lnk)

    def _get_clink_ptr(self):
        return _ida_pro.qstrvec_t_get_clink_ptr(self)

    def assign(self, other):
        """Copies the contents of 'other' to 'self'"""
        return _ida_pro.qstrvec_t_assign(self, other)

    def __setitem__(self, idx, s):
        """Sets string at the given index"""
        return _ida_pro.qstrvec_t_set(self, idx, s)

    def __getitem__(self, idx):
        """Gets the string at the given index"""
        return _ida_pro.qstrvec_t_get(self, idx)

    def __get_size(self):
        return _ida_pro.qstrvec_t_size(self)

    size = property(__get_size)
    """Returns the count of elements"""

    def addressof(self, idx):
        """Returns the address (as number) of the qstring at the given index"""
        return _ida_pro.qstrvec_t_addressof(self, idx)

    def add(self, s):
        """Add a string to the vector"""
        return _ida_pro.qstrvec_t_add(self, s)

    def from_list(self, lst):
        """Populates the vector from a Python string list"""
        return _ida_pro.qstrvec_t_from_list(self, lst)

    def clear(self, qclear=False):
        """
        Clears all strings from the vector.
        @param qclear: Just reset the size but do not actually free the memory
        """
        return _ida_pro.qstrvec_t_clear(self, qclear)

    def insert(self, idx, s):
        """Insert a string into the vector"""
        return _ida_pro.qstrvec_t_insert(self, idx, s)

    def remove(self, idx):
        """Removes a string from the vector"""
        return _ida_pro.qstrvec_t_remove(self, idx)

#</pycode(py_pro)>
