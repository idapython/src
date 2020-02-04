# This file was automatically generated by SWIG (http://www.swig.org).
# Version 4.0.1
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.

"""IDA Plugin SDK API wrapper: segment"""

from sys import version_info as _swig_python_version_info
if _swig_python_version_info < (2, 7, 0):
    raise RuntimeError("Python 2.7 or later required")

# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_segment
else:
    import _ida_segment

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

import ida_range
SREG_NUM = _ida_segment.SREG_NUM

class segment_t(ida_range.range_t):
    r"""Proxy of C++ segment_t class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""__init__(self) -> segment_t"""
        _ida_segment.segment_t_swiginit(self, _ida_segment.new_segment_t(*args))
    name = property(_ida_segment.segment_t_name_get, _ida_segment.segment_t_name_set, doc=r"""name""")
    sclass = property(_ida_segment.segment_t_sclass_get, _ida_segment.segment_t_sclass_set, doc=r"""sclass""")
    orgbase = property(_ida_segment.segment_t_orgbase_get, _ida_segment.segment_t_orgbase_set, doc=r"""orgbase""")
    align = property(_ida_segment.segment_t_align_get, _ida_segment.segment_t_align_set, doc=r"""align""")
    comb = property(_ida_segment.segment_t_comb_get, _ida_segment.segment_t_comb_set, doc=r"""comb""")
    perm = property(_ida_segment.segment_t_perm_get, _ida_segment.segment_t_perm_set, doc=r"""perm""")
    bitness = property(_ida_segment.segment_t_bitness_get, _ida_segment.segment_t_bitness_set, doc=r"""bitness""")

    def use32(self, *args):
        r"""use32(self) -> bool"""
        return _ida_segment.segment_t_use32(self, *args)

    def use64(self, *args):
        r"""use64(self) -> bool"""
        return _ida_segment.segment_t_use64(self, *args)

    def abits(self, *args):
        r"""abits(self) -> int"""
        return _ida_segment.segment_t_abits(self, *args)

    def abytes(self, *args):
        r"""abytes(self) -> int"""
        return _ida_segment.segment_t_abytes(self, *args)
    flags = property(_ida_segment.segment_t_flags_get, _ida_segment.segment_t_flags_set, doc=r"""flags""")

    def comorg(self, *args):
        r"""comorg(self) -> bool"""
        return _ida_segment.segment_t_comorg(self, *args)

    def set_comorg(self, *args):
        r"""set_comorg(self)"""
        return _ida_segment.segment_t_set_comorg(self, *args)

    def clr_comorg(self, *args):
        r"""clr_comorg(self)"""
        return _ida_segment.segment_t_clr_comorg(self, *args)

    def ob_ok(self, *args):
        r"""ob_ok(self) -> bool"""
        return _ida_segment.segment_t_ob_ok(self, *args)

    def set_ob_ok(self, *args):
        r"""set_ob_ok(self)"""
        return _ida_segment.segment_t_set_ob_ok(self, *args)

    def clr_ob_ok(self, *args):
        r"""clr_ob_ok(self)"""
        return _ida_segment.segment_t_clr_ob_ok(self, *args)

    def is_visible_segm(self, *args):
        r"""is_visible_segm(self) -> bool"""
        return _ida_segment.segment_t_is_visible_segm(self, *args)

    def set_visible_segm(self, *args):
        r"""set_visible_segm(self, visible)"""
        return _ida_segment.segment_t_set_visible_segm(self, *args)

    def set_debugger_segm(self, *args):
        r"""set_debugger_segm(self, debseg)"""
        return _ida_segment.segment_t_set_debugger_segm(self, *args)

    def is_loader_segm(self, *args):
        r"""is_loader_segm(self) -> bool"""
        return _ida_segment.segment_t_is_loader_segm(self, *args)

    def set_loader_segm(self, *args):
        r"""set_loader_segm(self, ldrseg)"""
        return _ida_segment.segment_t_set_loader_segm(self, *args)

    def is_hidden_segtype(self, *args):
        r"""is_hidden_segtype(self) -> bool"""
        return _ida_segment.segment_t_is_hidden_segtype(self, *args)

    def set_hidden_segtype(self, *args):
        r"""set_hidden_segtype(self, hide)"""
        return _ida_segment.segment_t_set_hidden_segtype(self, *args)

    def is_header_segm(self, *args):
        r"""is_header_segm(self) -> bool"""
        return _ida_segment.segment_t_is_header_segm(self, *args)

    def set_header_segm(self, *args):
        r"""set_header_segm(self, on)"""
        return _ida_segment.segment_t_set_header_segm(self, *args)
    sel = property(_ida_segment.segment_t_sel_get, _ida_segment.segment_t_sel_set, doc=r"""sel""")
    defsr = property(_ida_segment.segment_t_defsr_get, _ida_segment.segment_t_defsr_set, doc=r"""defsr""")
    type = property(_ida_segment.segment_t_type_get, _ida_segment.segment_t_type_set, doc=r"""type""")
    color = property(_ida_segment.segment_t_color_get, _ida_segment.segment_t_color_set, doc=r"""color""")

    def update(self, *args):
        r"""update(self) -> bool"""
        return _ida_segment.segment_t_update(self, *args)
    start_ea = property(_ida_segment.segment_t_start_ea_get, _ida_segment.segment_t_start_ea_set, doc=r"""start_ea""")
    end_ea = property(_ida_segment.segment_t_end_ea_get, _ida_segment.segment_t_end_ea_set, doc=r"""end_ea""")
    __swig_destroy__ = _ida_segment.delete_segment_t

# Register segment_t in _ida_segment:
_ida_segment.segment_t_swigregister(segment_t)
saAbs = _ida_segment.saAbs

saRelByte = _ida_segment.saRelByte

saRelWord = _ida_segment.saRelWord

saRelPara = _ida_segment.saRelPara

saRelPage = _ida_segment.saRelPage

saRelDble = _ida_segment.saRelDble

saRel4K = _ida_segment.saRel4K

saGroup = _ida_segment.saGroup

saRel32Bytes = _ida_segment.saRel32Bytes

saRel64Bytes = _ida_segment.saRel64Bytes

saRelQword = _ida_segment.saRelQword

saRel128Bytes = _ida_segment.saRel128Bytes

saRel512Bytes = _ida_segment.saRel512Bytes

saRel1024Bytes = _ida_segment.saRel1024Bytes

saRel2048Bytes = _ida_segment.saRel2048Bytes

saRel_MAX_ALIGN_CODE = _ida_segment.saRel_MAX_ALIGN_CODE

scPriv = _ida_segment.scPriv

scGroup = _ida_segment.scGroup

scPub = _ida_segment.scPub

scPub2 = _ida_segment.scPub2

scStack = _ida_segment.scStack

scCommon = _ida_segment.scCommon

scPub3 = _ida_segment.scPub3

sc_MAX_COMB_CODE = _ida_segment.sc_MAX_COMB_CODE

SEGPERM_EXEC = _ida_segment.SEGPERM_EXEC

SEGPERM_WRITE = _ida_segment.SEGPERM_WRITE

SEGPERM_READ = _ida_segment.SEGPERM_READ

SEGPERM_MAXVAL = _ida_segment.SEGPERM_MAXVAL

SEG_MAX_BITNESS_CODE = _ida_segment.SEG_MAX_BITNESS_CODE

SFL_COMORG = _ida_segment.SFL_COMORG

SFL_OBOK = _ida_segment.SFL_OBOK

SFL_HIDDEN = _ida_segment.SFL_HIDDEN

SFL_DEBUG = _ida_segment.SFL_DEBUG

SFL_LOADER = _ida_segment.SFL_LOADER

SFL_HIDETYPE = _ida_segment.SFL_HIDETYPE

SFL_HEADER = _ida_segment.SFL_HEADER

SEG_NORM = _ida_segment.SEG_NORM

SEG_XTRN = _ida_segment.SEG_XTRN

SEG_CODE = _ida_segment.SEG_CODE

SEG_DATA = _ida_segment.SEG_DATA

SEG_IMP = _ida_segment.SEG_IMP

SEG_GRP = _ida_segment.SEG_GRP

SEG_NULL = _ida_segment.SEG_NULL

SEG_UNDF = _ida_segment.SEG_UNDF

SEG_BSS = _ida_segment.SEG_BSS

SEG_ABSSYM = _ida_segment.SEG_ABSSYM

SEG_COMM = _ida_segment.SEG_COMM

SEG_IMEM = _ida_segment.SEG_IMEM

SEG_MAX_SEGTYPE_CODE = _ida_segment.SEG_MAX_SEGTYPE_CODE



def is_visible_segm(*args):
    r"""is_visible_segm(s) -> bool"""
    return _ida_segment.is_visible_segm(*args)

def is_finally_visible_segm(*args):
    r"""is_finally_visible_segm(s) -> bool"""
    return _ida_segment.is_finally_visible_segm(*args)

def set_visible_segm(*args):
    r"""set_visible_segm(s, visible)"""
    return _ida_segment.set_visible_segm(*args)

def is_spec_segm(*args):
    r"""is_spec_segm(seg_type) -> bool"""
    return _ida_segment.is_spec_segm(*args)

def is_spec_ea(*args):
    r"""is_spec_ea(ea) -> bool"""
    return _ida_segment.is_spec_ea(*args)

def lock_segm(*args):
    r"""lock_segm(segm, lock)"""
    return _ida_segment.lock_segm(*args)
class lock_segment(object):
    r"""Proxy of C++ lock_segment class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""__init__(self, _segm) -> lock_segment"""
        _ida_segment.lock_segment_swiginit(self, _ida_segment.new_lock_segment(*args))
    __swig_destroy__ = _ida_segment.delete_lock_segment

# Register lock_segment in _ida_segment:
_ida_segment.lock_segment_swigregister(lock_segment)


def is_segm_locked(*args):
    r"""is_segm_locked(segm) -> bool"""
    return _ida_segment.is_segm_locked(*args)

def getn_selector(*args):
    r"""getn_selector(n) -> bool"""
    return _ida_segment.getn_selector(*args)

def get_selector_qty(*args):
    r"""get_selector_qty() -> int"""
    return _ida_segment.get_selector_qty(*args)

def setup_selector(*args):
    r"""setup_selector(segbase) -> sel_t"""
    return _ida_segment.setup_selector(*args)

def allocate_selector(*args):
    r"""allocate_selector(segbase) -> sel_t"""
    return _ida_segment.allocate_selector(*args)

def find_free_selector(*args):
    r"""find_free_selector() -> sel_t"""
    return _ida_segment.find_free_selector(*args)

def set_selector(*args):
    r"""set_selector(selector, paragraph) -> int"""
    return _ida_segment.set_selector(*args)

def del_selector(*args):
    r"""del_selector(selector)"""
    return _ida_segment.del_selector(*args)

def sel2para(*args):
    r"""sel2para(selector) -> ea_t"""
    return _ida_segment.sel2para(*args)

def sel2ea(*args):
    r"""sel2ea(selector) -> ea_t"""
    return _ida_segment.sel2ea(*args)

def find_selector(*args):
    r"""find_selector(base) -> sel_t"""
    return _ida_segment.find_selector(*args)

def get_segm_by_sel(*args):
    r"""get_segm_by_sel(selector) -> segment_t"""
    return _ida_segment.get_segm_by_sel(*args)

def add_segm_ex(*args):
    r"""add_segm_ex(s, name, sclass, flags) -> bool"""
    return _ida_segment.add_segm_ex(*args)
ADDSEG_NOSREG = _ida_segment.ADDSEG_NOSREG

ADDSEG_OR_DIE = _ida_segment.ADDSEG_OR_DIE

ADDSEG_NOTRUNC = _ida_segment.ADDSEG_NOTRUNC

ADDSEG_QUIET = _ida_segment.ADDSEG_QUIET

ADDSEG_FILLGAP = _ida_segment.ADDSEG_FILLGAP

ADDSEG_SPARSE = _ida_segment.ADDSEG_SPARSE

ADDSEG_NOAA = _ida_segment.ADDSEG_NOAA

ADDSEG_IDBENC = _ida_segment.ADDSEG_IDBENC


def add_segm(*args):
    r"""add_segm(para, start, end, name, sclass, flags=0) -> bool"""
    return _ida_segment.add_segm(*args)

def del_segm(*args):
    r"""del_segm(ea, flags) -> bool"""
    return _ida_segment.del_segm(*args)
SEGMOD_KILL = _ida_segment.SEGMOD_KILL

SEGMOD_KEEP = _ida_segment.SEGMOD_KEEP

SEGMOD_SILENT = _ida_segment.SEGMOD_SILENT

SEGMOD_KEEP0 = _ida_segment.SEGMOD_KEEP0

SEGMOD_KEEPSEL = _ida_segment.SEGMOD_KEEPSEL

SEGMOD_NOMOVE = _ida_segment.SEGMOD_NOMOVE

SEGMOD_SPARSE = _ida_segment.SEGMOD_SPARSE


def get_segm_qty(*args):
    r"""get_segm_qty() -> int"""
    return _ida_segment.get_segm_qty(*args)

def getseg(*args):
    r"""getseg(ea) -> segment_t"""
    return _ida_segment.getseg(*args)

def getnseg(*args):
    r"""getnseg(n) -> segment_t"""
    return _ida_segment.getnseg(*args)

def get_segm_num(*args):
    r"""get_segm_num(ea) -> int"""
    return _ida_segment.get_segm_num(*args)

def get_next_seg(*args):
    r"""get_next_seg(ea) -> segment_t"""
    return _ida_segment.get_next_seg(*args)

def get_prev_seg(*args):
    r"""get_prev_seg(ea) -> segment_t"""
    return _ida_segment.get_prev_seg(*args)

def get_first_seg(*args):
    r"""get_first_seg() -> segment_t"""
    return _ida_segment.get_first_seg(*args)

def get_last_seg(*args):
    r"""get_last_seg() -> segment_t"""
    return _ida_segment.get_last_seg(*args)

def get_segm_by_name(*args):
    r"""get_segm_by_name(name) -> segment_t"""
    return _ida_segment.get_segm_by_name(*args)

def set_segm_end(*args):
    r"""set_segm_end(ea, newend, flags) -> bool"""
    return _ida_segment.set_segm_end(*args)

def set_segm_start(*args):
    r"""set_segm_start(ea, newstart, flags) -> bool"""
    return _ida_segment.set_segm_start(*args)

def move_segm_start(*args):
    r"""move_segm_start(ea, newstart, mode) -> bool"""
    return _ida_segment.move_segm_start(*args)

def move_segm(*args):
    r"""move_segm(s, to, flags=0) -> int"""
    return _ida_segment.move_segm(*args)
MSF_SILENT = _ida_segment.MSF_SILENT

MSF_NOFIX = _ida_segment.MSF_NOFIX

MSF_LDKEEP = _ida_segment.MSF_LDKEEP

MSF_FIXONCE = _ida_segment.MSF_FIXONCE

MFS_NETMAP = _ida_segment.MFS_NETMAP

MSF_PRIORITY = _ida_segment.MSF_PRIORITY

MOVE_SEGM_OK = _ida_segment.MOVE_SEGM_OK

MOVE_SEGM_PARAM = _ida_segment.MOVE_SEGM_PARAM

MOVE_SEGM_ROOM = _ida_segment.MOVE_SEGM_ROOM

MOVE_SEGM_IDP = _ida_segment.MOVE_SEGM_IDP

MOVE_SEGM_CHUNK = _ida_segment.MOVE_SEGM_CHUNK

MOVE_SEGM_LOADER = _ida_segment.MOVE_SEGM_LOADER

MOVE_SEGM_ODD = _ida_segment.MOVE_SEGM_ODD

MOVE_SEGM_ORPHAN = _ida_segment.MOVE_SEGM_ORPHAN


def change_segment_status(*args):
    r"""change_segment_status(s, is_deb_segm) -> int"""
    return _ida_segment.change_segment_status(*args)
CSS_OK = _ida_segment.CSS_OK

CSS_NODBG = _ida_segment.CSS_NODBG

CSS_NORANGE = _ida_segment.CSS_NORANGE

CSS_NOMEM = _ida_segment.CSS_NOMEM

CSS_BREAK = _ida_segment.CSS_BREAK


def take_memory_snapshot(*args):
    r"""take_memory_snapshot(only_loader_segs) -> bool"""
    return _ida_segment.take_memory_snapshot(*args)

def is_miniidb(*args):
    r"""is_miniidb() -> bool"""
    return _ida_segment.is_miniidb(*args)

def set_segm_base(*args):
    r"""set_segm_base(s, newbase) -> bool"""
    return _ida_segment.set_segm_base(*args)

def set_group_selector(*args):
    r"""set_group_selector(grp, sel) -> int"""
    return _ida_segment.set_group_selector(*args)
MAX_GROUPS = _ida_segment.MAX_GROUPS


def get_group_selector(*args):
    r"""get_group_selector(grpsel) -> sel_t"""
    return _ida_segment.get_group_selector(*args)

def add_segment_translation(*args):
    r"""add_segment_translation(segstart, mappedseg) -> bool"""
    return _ida_segment.add_segment_translation(*args)
MAX_SEGM_TRANSLATIONS = _ida_segment.MAX_SEGM_TRANSLATIONS


def set_segment_translations(*args):
    r"""set_segment_translations(segstart, transmap) -> bool"""
    return _ida_segment.set_segment_translations(*args)

def del_segment_translations(*args):
    r"""del_segment_translations(segstart)"""
    return _ida_segment.del_segment_translations(*args)

def get_segment_translations(*args):
    r"""get_segment_translations(transmap, segstart) -> ssize_t"""
    return _ida_segment.get_segment_translations(*args)

def get_segment_cmt(*args):
    r"""get_segment_cmt(s, repeatable) -> ssize_t"""
    return _ida_segment.get_segment_cmt(*args)

def set_segment_cmt(*args):
    r"""set_segment_cmt(s, cmt, repeatable)"""
    return _ida_segment.set_segment_cmt(*args)

def std_out_segm_footer(*args):
    r"""std_out_segm_footer(ctx, seg)"""
    return _ida_segment.std_out_segm_footer(*args)

def set_segm_name(*args):
    r"""set_segm_name(s, name, flags=0) -> int"""
    return _ida_segment.set_segm_name(*args)

def get_segm_name(*args):
    r"""get_segm_name(s, flags=0) -> ssize_t"""
    return _ida_segment.get_segm_name(*args)

def get_visible_segm_name(*args):
    r"""get_visible_segm_name(s) -> ssize_t"""
    return _ida_segment.get_visible_segm_name(*args)

def get_segm_class(*args):
    r"""get_segm_class(s) -> ssize_t"""
    return _ida_segment.get_segm_class(*args)

def set_segm_class(*args):
    r"""set_segm_class(s, sclass, flags=0) -> int"""
    return _ida_segment.set_segm_class(*args)

def segtype(*args):
    r"""segtype(ea) -> uchar"""
    return _ida_segment.segtype(*args)

def get_segment_alignment(*args):
    r"""get_segment_alignment(align) -> char const *"""
    return _ida_segment.get_segment_alignment(*args)

def get_segment_combination(*args):
    r"""get_segment_combination(comb) -> char const *"""
    return _ida_segment.get_segment_combination(*args)

def get_segm_para(*args):
    r"""get_segm_para(s) -> ea_t"""
    return _ida_segment.get_segm_para(*args)

def get_segm_base(*args):
    r"""get_segm_base(s) -> ea_t"""
    return _ida_segment.get_segm_base(*args)

def set_segm_addressing(*args):
    r"""set_segm_addressing(s, bitness) -> bool"""
    return _ida_segment.set_segm_addressing(*args)

def update_segm(*args):
    r"""update_segm(s) -> bool"""
    return _ida_segment.update_segm(*args)

def segm_adjust_diff(*args):
    r"""segm_adjust_diff(s, delta) -> adiff_t"""
    return _ida_segment.segm_adjust_diff(*args)

def segm_adjust_ea(*args):
    r"""segm_adjust_ea(s, ea) -> ea_t"""
    return _ida_segment.segm_adjust_ea(*args)

def get_defsr(*args):
    r"""get_defsr(s, reg) -> sel_t"""
    return _ida_segment.get_defsr(*args)

def set_defsr(*args):
    r"""set_defsr(s, reg, value)"""
    return _ida_segment.set_defsr(*args)

def rebase_program(*args):
    r"""rebase_program(delta, flags) -> int"""
    return _ida_segment.rebase_program(*args)

if _BC695:
    CSS_NOAREA=CSS_NORANGE
    SEGDEL_KEEP=SEGMOD_KEEP
    SEGDEL_KEEP0=SEGMOD_KEEP0
    SEGDEL_PERM=SEGMOD_KILL
    SEGDEL_SILENT=SEGMOD_SILENT
    def del_segment_cmt(s, rpt):
        set_segment_cmt(s, "", rpt)
    ask_selector=sel2para
# In 7.0, those were renamed
#  - get_true_segm_name -> get_segm_name
#  - get_segm_name -> get_visible_segm_name
# alas, since they have the same prototypes, we cannot do much,
# but redirect all to get_segm_name and hope for the best
    get_true_segm_name=get_segm_name




