# This file was automatically generated by SWIG (http://www.swig.org).
# Version 4.0.1
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.

"""IDA Plugin SDK API wrapper: struct"""

from sys import version_info as _swig_python_version_info
if _swig_python_version_info < (2, 7, 0):
    raise RuntimeError("Python 2.7 or later required")

# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_struct
else:
    import _ida_struct

try:
    import builtins as __builtin__
except ImportError:
    import __builtin__

def _swig_repr(self):
    try:
        strthis = "proxy of " + self.this.__repr__()
    except __builtin__.Exception:
        strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)


def _swig_setattr_nondynamic_instance_variable(set):
    def set_instance_attr(self, name, value):
        if name == "thisown":
            self.this.own(value)
        elif name == "this":
            set(self, name, value)
        elif hasattr(self, name) and isinstance(getattr(type(self), name), property):
            set(self, name, value)
        else:
            raise AttributeError("You cannot add instance attributes to %s" % self)
    return set_instance_attr


def _swig_setattr_nondynamic_class_variable(set):
    def set_class_attr(cls, name, value):
        if hasattr(cls, name) and not isinstance(getattr(cls, name), property):
            set(cls, name, value)
        else:
            raise AttributeError("You cannot add class attributes to %s" % cls)
    return set_class_attr


def _swig_add_metaclass(metaclass):
    """Class decorator for adding a metaclass to a SWIG wrapped class - a slimmed down version of six.add_metaclass"""
    def wrapper(cls):
        return metaclass(cls.__name__, cls.__bases__, cls.__dict__.copy())
    return wrapper


class _SwigNonDynamicMeta(type):
    """Meta class to enforce nondynamic attributes (no new attributes) for a class"""
    __setattr__ = _swig_setattr_nondynamic_class_variable(type.__setattr__)


import weakref


import ida_idaapi


import sys
_BC695 = sys.modules["__main__"].IDAPYTHON_COMPAT_695_API

if _BC695:






    def bc695redef(func):
        ida_idaapi._BC695.replace_fun(func)
        return func


def get_member_size(*args):
    r"""get_member_size(nonnul_mptr) -> asize_t"""
    return _ida_struct.get_member_size(*args)
STRUC_SEPARATOR = _ida_struct.STRUC_SEPARATOR

class member_t(object):
    r"""Proxy of C++ member_t class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    id = property(_ida_struct.member_t_id_get, _ida_struct.member_t_id_set, doc=r"""id""")
    soff = property(_ida_struct.member_t_soff_get, _ida_struct.member_t_soff_set, doc=r"""soff""")
    eoff = property(_ida_struct.member_t_eoff_get, _ida_struct.member_t_eoff_set, doc=r"""eoff""")
    flag = property(_ida_struct.member_t_flag_get, _ida_struct.member_t_flag_set, doc=r"""flag""")
    props = property(_ida_struct.member_t_props_get, _ida_struct.member_t_props_set, doc=r"""props""")

    def unimem(self, *args):
        r"""unimem(self) -> bool"""
        return _ida_struct.member_t_unimem(self, *args)

    def has_union(self, *args):
        r"""has_union(self) -> bool"""
        return _ida_struct.member_t_has_union(self, *args)

    def by_til(self, *args):
        r"""by_til(self) -> bool"""
        return _ida_struct.member_t_by_til(self, *args)

    def has_ti(self, *args):
        r"""has_ti(self) -> bool"""
        return _ida_struct.member_t_has_ti(self, *args)

    def is_baseclass(self, *args):
        r"""is_baseclass(self) -> bool"""
        return _ida_struct.member_t_is_baseclass(self, *args)

    def is_dupname(self, *args):
        r"""is_dupname(self) -> bool"""
        return _ida_struct.member_t_is_dupname(self, *args)

    def is_destructor(self, *args):
        r"""is_destructor(self) -> bool"""
        return _ida_struct.member_t_is_destructor(self, *args)

    def get_soff(self, *args):
        r"""get_soff(self) -> ea_t"""
        return _ida_struct.member_t_get_soff(self, *args)

    def __init__(self, *args):
        r"""__init__(self) -> member_t"""
        _ida_struct.member_t_swiginit(self, _ida_struct.new_member_t(*args))
    __swig_destroy__ = _ida_struct.delete_member_t

# Register member_t in _ida_struct:
_ida_struct.member_t_swigregister(member_t)
MF_OK = _ida_struct.MF_OK

MF_UNIMEM = _ida_struct.MF_UNIMEM

MF_HASUNI = _ida_struct.MF_HASUNI

MF_BYTIL = _ida_struct.MF_BYTIL

MF_HASTI = _ida_struct.MF_HASTI

MF_BASECLASS = _ida_struct.MF_BASECLASS

MF_DTOR = _ida_struct.MF_DTOR

MF_DUPNAME = _ida_struct.MF_DUPNAME


class struc_t(object):
    r"""Proxy of C++ struc_t class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")

    def __init__(self, *args, **kwargs):
        raise AttributeError("No constructor defined")
    __repr__ = _swig_repr
    id = property(_ida_struct.struc_t_id_get, _ida_struct.struc_t_id_set, doc=r"""id""")
    memqty = property(_ida_struct.struc_t_memqty_get, _ida_struct.struc_t_memqty_set, doc=r"""memqty""")
    members = property(_ida_struct.struc_t_members_get, _ida_struct.struc_t_members_set, doc=r"""members""")
    age = property(_ida_struct.struc_t_age_get, _ida_struct.struc_t_age_set, doc=r"""age""")
    props = property(_ida_struct.struc_t_props_get, _ida_struct.struc_t_props_set, doc=r"""props""")

    def is_varstr(self, *args):
        r"""is_varstr(self) -> bool"""
        return _ida_struct.struc_t_is_varstr(self, *args)

    def is_union(self, *args):
        r"""is_union(self) -> bool"""
        return _ida_struct.struc_t_is_union(self, *args)

    def has_union(self, *args):
        r"""has_union(self) -> bool"""
        return _ida_struct.struc_t_has_union(self, *args)

    def is_choosable(self, *args):
        r"""is_choosable(self) -> bool"""
        return _ida_struct.struc_t_is_choosable(self, *args)

    def from_til(self, *args):
        r"""from_til(self) -> bool"""
        return _ida_struct.struc_t_from_til(self, *args)

    def is_hidden(self, *args):
        r"""is_hidden(self) -> bool"""
        return _ida_struct.struc_t_is_hidden(self, *args)

    def is_frame(self, *args):
        r"""is_frame(self) -> bool"""
        return _ida_struct.struc_t_is_frame(self, *args)

    def get_alignment(self, *args):
        r"""get_alignment(self) -> int"""
        return _ida_struct.struc_t_get_alignment(self, *args)

    def is_ghost(self, *args):
        r"""is_ghost(self) -> bool"""
        return _ida_struct.struc_t_is_ghost(self, *args)

    def set_alignment(self, *args):
        r"""set_alignment(self, shift)"""
        return _ida_struct.struc_t_set_alignment(self, *args)

    def set_ghost(self, *args):
        r"""set_ghost(self, _is_ghost)"""
        return _ida_struct.struc_t_set_ghost(self, *args)
    ordinal = property(_ida_struct.struc_t_ordinal_get, _ida_struct.struc_t_ordinal_set, doc=r"""ordinal""")

    def get_member(self, *args):
        r"""get_member(self, index) -> member_t"""
        return _ida_struct.struc_t_get_member(self, *args)
    __swig_destroy__ = _ida_struct.delete_struc_t

# Register struc_t in _ida_struct:
_ida_struct.struc_t_swigregister(struc_t)
SF_VAR = _ida_struct.SF_VAR

SF_UNION = _ida_struct.SF_UNION

SF_HASUNI = _ida_struct.SF_HASUNI

SF_NOLIST = _ida_struct.SF_NOLIST

SF_TYPLIB = _ida_struct.SF_TYPLIB

SF_HIDDEN = _ida_struct.SF_HIDDEN

SF_FRAME = _ida_struct.SF_FRAME

SF_ALIGN = _ida_struct.SF_ALIGN

SF_GHOST = _ida_struct.SF_GHOST



def get_struc_qty(*args):
    r"""get_struc_qty() -> size_t"""
    return _ida_struct.get_struc_qty(*args)

def get_first_struc_idx(*args):
    r"""get_first_struc_idx() -> uval_t"""
    return _ida_struct.get_first_struc_idx(*args)

def get_last_struc_idx(*args):
    r"""get_last_struc_idx() -> uval_t"""
    return _ida_struct.get_last_struc_idx(*args)

def get_prev_struc_idx(*args):
    r"""get_prev_struc_idx(idx) -> uval_t"""
    return _ida_struct.get_prev_struc_idx(*args)

def get_next_struc_idx(*args):
    r"""get_next_struc_idx(idx) -> uval_t"""
    return _ida_struct.get_next_struc_idx(*args)

def get_struc_idx(*args):
    r"""get_struc_idx(id) -> uval_t"""
    return _ida_struct.get_struc_idx(*args)

def get_struc_by_idx(*args):
    r"""get_struc_by_idx(idx) -> tid_t"""
    return _ida_struct.get_struc_by_idx(*args)

def get_struc(*args):
    r"""get_struc(id) -> struc_t"""
    return _ida_struct.get_struc(*args)

def get_struc_id(*args):
    r"""get_struc_id(name) -> tid_t"""
    return _ida_struct.get_struc_id(*args)

def get_struc_name(*args):
    r"""get_struc_name(id) -> ssize_t"""
    return _ida_struct.get_struc_name(*args)

def get_struc_cmt(*args):
    r"""get_struc_cmt(id, repeatable) -> ssize_t"""
    return _ida_struct.get_struc_cmt(*args)

def get_struc_size(*args):
    r"""
    get_struc_size(sptr) -> asize_t
    get_struc_size(id) -> asize_t
    """
    return _ida_struct.get_struc_size(*args)

def get_struc_prev_offset(*args):
    r"""get_struc_prev_offset(sptr, offset) -> ea_t"""
    return _ida_struct.get_struc_prev_offset(*args)

def get_struc_next_offset(*args):
    r"""get_struc_next_offset(sptr, offset) -> ea_t"""
    return _ida_struct.get_struc_next_offset(*args)

def get_struc_last_offset(*args):
    r"""get_struc_last_offset(sptr) -> ea_t"""
    return _ida_struct.get_struc_last_offset(*args)

def get_struc_first_offset(*args):
    r"""get_struc_first_offset(sptr) -> ea_t"""
    return _ida_struct.get_struc_first_offset(*args)

def get_max_offset(*args):
    r"""get_max_offset(sptr) -> ea_t"""
    return _ida_struct.get_max_offset(*args)

def is_varstr(*args):
    r"""is_varstr(id) -> bool"""
    return _ida_struct.is_varstr(*args)

def is_union(*args):
    r"""is_union(id) -> bool"""
    return _ida_struct.is_union(*args)

def get_member_struc(*args):
    r"""get_member_struc(fullname) -> struc_t"""
    return _ida_struct.get_member_struc(*args)

def get_sptr(*args):
    r"""get_sptr(mptr) -> struc_t"""
    return _ida_struct.get_sptr(*args)

def get_member(*args):
    r"""get_member(sptr, offset) -> member_t"""
    return _ida_struct.get_member(*args)

def get_member_by_name(*args):
    r"""get_member_by_name(sptr, membername) -> member_t"""
    return _ida_struct.get_member_by_name(*args)

def get_member_by_fullname(*args):
    r"""get_member_by_fullname(fullname) -> member_t"""
    return _ida_struct.get_member_by_fullname(*args)

def get_member_fullname(*args):
    r"""get_member_fullname(mid) -> ssize_t"""
    return _ida_struct.get_member_fullname(*args)

def get_member_name(*args):
    r"""get_member_name(mid) -> ssize_t"""
    return _ida_struct.get_member_name(*args)

def get_member_cmt(*args):
    r"""get_member_cmt(mid, repeatable) -> ssize_t"""
    return _ida_struct.get_member_cmt(*args)

def is_varmember(*args):
    r"""is_varmember(mptr) -> bool"""
    return _ida_struct.is_varmember(*args)

def get_best_fit_member(*args):
    r"""get_best_fit_member(sptr, offset) -> member_t"""
    return _ida_struct.get_best_fit_member(*args)

def get_next_member_idx(*args):
    r"""get_next_member_idx(sptr, off) -> ssize_t"""
    return _ida_struct.get_next_member_idx(*args)

def get_prev_member_idx(*args):
    r"""get_prev_member_idx(sptr, off) -> ssize_t"""
    return _ida_struct.get_prev_member_idx(*args)

def add_struc(*args):
    r"""add_struc(idx, name, is_union=False) -> tid_t"""
    return _ida_struct.add_struc(*args)

def del_struc(*args):
    r"""del_struc(sptr) -> bool"""
    return _ida_struct.del_struc(*args)

def set_struc_idx(*args):
    r"""set_struc_idx(sptr, idx) -> bool"""
    return _ida_struct.set_struc_idx(*args)

def set_struc_align(*args):
    r"""set_struc_align(sptr, shift) -> bool"""
    return _ida_struct.set_struc_align(*args)

def set_struc_name(*args):
    r"""set_struc_name(id, name) -> bool"""
    return _ida_struct.set_struc_name(*args)

def set_struc_cmt(*args):
    r"""set_struc_cmt(id, cmt, repeatable) -> bool"""
    return _ida_struct.set_struc_cmt(*args)
STRUC_ERROR_MEMBER_OK = _ida_struct.STRUC_ERROR_MEMBER_OK

STRUC_ERROR_MEMBER_NAME = _ida_struct.STRUC_ERROR_MEMBER_NAME

STRUC_ERROR_MEMBER_OFFSET = _ida_struct.STRUC_ERROR_MEMBER_OFFSET

STRUC_ERROR_MEMBER_SIZE = _ida_struct.STRUC_ERROR_MEMBER_SIZE

STRUC_ERROR_MEMBER_TINFO = _ida_struct.STRUC_ERROR_MEMBER_TINFO

STRUC_ERROR_MEMBER_STRUCT = _ida_struct.STRUC_ERROR_MEMBER_STRUCT

STRUC_ERROR_MEMBER_UNIVAR = _ida_struct.STRUC_ERROR_MEMBER_UNIVAR

STRUC_ERROR_MEMBER_VARLAST = _ida_struct.STRUC_ERROR_MEMBER_VARLAST

STRUC_ERROR_MEMBER_NESTED = _ida_struct.STRUC_ERROR_MEMBER_NESTED


def add_struc_member(*args):
    r"""add_struc_member(sptr, fieldname, offset, flag, mt, nbytes) -> struc_error_t"""
    return _ida_struct.add_struc_member(*args)

def del_struc_member(*args):
    r"""del_struc_member(sptr, offset) -> bool"""
    return _ida_struct.del_struc_member(*args)

def del_struc_members(*args):
    r"""del_struc_members(sptr, off1, off2) -> int"""
    return _ida_struct.del_struc_members(*args)

def set_member_name(*args):
    r"""set_member_name(sptr, offset, name) -> bool"""
    return _ida_struct.set_member_name(*args)

def set_member_type(*args):
    r"""set_member_type(sptr, offset, flag, mt, nbytes) -> bool"""
    return _ida_struct.set_member_type(*args)

def set_member_cmt(*args):
    r"""set_member_cmt(mptr, cmt, repeatable) -> bool"""
    return _ida_struct.set_member_cmt(*args)

def expand_struc(*args):
    r"""expand_struc(sptr, offset, delta, recalc=True) -> bool"""
    return _ida_struct.expand_struc(*args)

def save_struc(*args):
    r"""save_struc(sptr, may_update_ltypes=True)"""
    return _ida_struct.save_struc(*args)

def set_struc_hidden(*args):
    r"""set_struc_hidden(sptr, is_hidden)"""
    return _ida_struct.set_struc_hidden(*args)

def set_struc_listed(*args):
    r"""set_struc_listed(sptr, is_listed)"""
    return _ida_struct.set_struc_listed(*args)
SMT_BADARG = _ida_struct.SMT_BADARG

SMT_NOCOMPAT = _ida_struct.SMT_NOCOMPAT

SMT_WORSE = _ida_struct.SMT_WORSE

SMT_SIZE = _ida_struct.SMT_SIZE

SMT_ARRAY = _ida_struct.SMT_ARRAY

SMT_OVERLAP = _ida_struct.SMT_OVERLAP

SMT_FAILED = _ida_struct.SMT_FAILED

SMT_OK = _ida_struct.SMT_OK

SMT_KEEP = _ida_struct.SMT_KEEP


def get_member_tinfo(*args):
    r"""get_member_tinfo(tif, mptr) -> bool"""
    return _ida_struct.get_member_tinfo(*args)

def del_member_tinfo(*args):
    r"""del_member_tinfo(sptr, mptr) -> bool"""
    return _ida_struct.del_member_tinfo(*args)

def set_member_tinfo(*args):
    r"""set_member_tinfo(sptr, mptr, memoff, tif, flags) -> smt_code_t"""
    return _ida_struct.set_member_tinfo(*args)
SET_MEMTI_MAY_DESTROY = _ida_struct.SET_MEMTI_MAY_DESTROY

SET_MEMTI_COMPATIBLE = _ida_struct.SET_MEMTI_COMPATIBLE

SET_MEMTI_FUNCARG = _ida_struct.SET_MEMTI_FUNCARG

SET_MEMTI_BYTIL = _ida_struct.SET_MEMTI_BYTIL

SET_MEMTI_USERTI = _ida_struct.SET_MEMTI_USERTI


def get_or_guess_member_tinfo(*args):
    r"""get_or_guess_member_tinfo(tif, mptr) -> bool"""
    return _ida_struct.get_or_guess_member_tinfo(*args)

def retrieve_member_info(*args):
    r"""retrieve_member_info(buf, mptr) -> opinfo_t"""
    return _ida_struct.retrieve_member_info(*args)

def is_anonymous_member_name(*args):
    r"""is_anonymous_member_name(name) -> bool"""
    return _ida_struct.is_anonymous_member_name(*args)

def is_dummy_member_name(*args):
    r"""is_dummy_member_name(name) -> bool"""
    return _ida_struct.is_dummy_member_name(*args)

def get_member_by_id(*args):
    r"""get_member_by_id(mid) -> member_t"""
    return _ida_struct.get_member_by_id(*args)

def is_member_id(*args):
    r"""is_member_id(mid) -> bool"""
    return _ida_struct.is_member_id(*args)

def is_special_member(*args):
    r"""is_special_member(id) -> bool"""
    return _ida_struct.is_special_member(*args)
class struct_field_visitor_t(object):
    r"""Proxy of C++ struct_field_visitor_t class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def visit_field(self, *args):
        r"""visit_field(self, sptr, mptr) -> int"""
        return _ida_struct.struct_field_visitor_t_visit_field(self, *args)

    def __init__(self, *args):
        r"""__init__(self) -> struct_field_visitor_t"""
        if self.__class__ == struct_field_visitor_t:
            _self = None
        else:
            _self = self
        _ida_struct.struct_field_visitor_t_swiginit(self, _ida_struct.new_struct_field_visitor_t(_self, *args))
    __swig_destroy__ = _ida_struct.delete_struct_field_visitor_t
    def __disown__(self):
        self.this.disown()
        _ida_struct.disown_struct_field_visitor_t(self)
        return weakref.proxy(self)

# Register struct_field_visitor_t in _ida_struct:
_ida_struct.struct_field_visitor_t_swigregister(struct_field_visitor_t)


def visit_stroff_fields(*args):
    r"""visit_stroff_fields(sfv, path, disp, appzero) -> flags_t"""
    return _ida_struct.visit_stroff_fields(*args)

def stroff_as_size(*args):
    r"""stroff_as_size(plen, sptr, value) -> bool"""
    return _ida_struct.stroff_as_size(*args)

if _BC695:
    get_member_name2=get_member_name
    def get_member_tinfo(*args):
        import ida_typeinf
        if isinstance(args[1], ida_typeinf.tinfo_t):  # 6.95: mptr, tinfo_t
            mptr, tif = args
        else:                                         # 7.00: tinfo_t, mptr
            tif, mptr = args
        return _ida_struct.get_member_tinfo(tif, mptr);
    def get_or_guess_member_tinfo(*args):
        import ida_typeinf
        if isinstance(args[1], ida_typeinf.tinfo_t):  # 6.95: mptr, tinfo_t
            mptr, tif = args
        else:                                         # 7.00: tinfo_t, mptr
            tif, mptr = args
        return _ida_struct.get_or_guess_member_tinfo(tif, mptr);
# note: if needed we might have to re-implement get_member_tinfo()
# and look whether there is a 2nd, 'tinfo_t' parameter (since the
# original get_member_tinfo function has a different signature)
    get_member_tinfo2=get_member_tinfo
# same here
    get_or_guess_member_tinfo2=get_or_guess_member_tinfo
    save_struc2=save_struc
    set_member_tinfo2=set_member_tinfo




