# This file was automatically generated by SWIG (http://www.swig.org).
# Version 4.0.1
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.

"""IDA Plugin SDK API wrapper: auto"""

from sys import version_info as _swig_python_version_info
if _swig_python_version_info < (2, 7, 0):
    raise RuntimeError("Python 2.7 or later required")

# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_auto
else:
    import _ida_auto

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


def get_auto_state(*args):
    r"""get_auto_state() -> atype_t"""
    return _ida_auto.get_auto_state(*args)

def set_auto_state(*args):
    r"""set_auto_state(new_state) -> atype_t"""
    return _ida_auto.set_auto_state(*args)
class auto_display_t(object):
    r"""Proxy of C++ auto_display_t class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    type = property(_ida_auto.auto_display_t_type_get, _ida_auto.auto_display_t_type_set, doc=r"""type""")
    ea = property(_ida_auto.auto_display_t_ea_get, _ida_auto.auto_display_t_ea_set, doc=r"""ea""")
    state = property(_ida_auto.auto_display_t_state_get, _ida_auto.auto_display_t_state_set, doc=r"""state""")

    def __init__(self, *args):
        r"""__init__(self) -> auto_display_t"""
        _ida_auto.auto_display_t_swiginit(self, _ida_auto.new_auto_display_t(*args))
    __swig_destroy__ = _ida_auto.delete_auto_display_t

# Register auto_display_t in _ida_auto:
_ida_auto.auto_display_t_swigregister(auto_display_t)
cvar = _ida_auto.cvar
AU_NONE = cvar.AU_NONE
AU_UNK = cvar.AU_UNK
AU_CODE = cvar.AU_CODE
AU_WEAK = cvar.AU_WEAK
AU_PROC = cvar.AU_PROC
AU_TAIL = cvar.AU_TAIL
AU_TRSP = cvar.AU_TRSP
AU_USED = cvar.AU_USED
AU_TYPE = cvar.AU_TYPE
AU_LIBF = cvar.AU_LIBF
AU_LBF2 = cvar.AU_LBF2
AU_LBF3 = cvar.AU_LBF3
AU_CHLB = cvar.AU_CHLB
AU_FINAL = cvar.AU_FINAL
st_Ready = cvar.st_Ready
st_Think = cvar.st_Think
st_Waiting = cvar.st_Waiting
st_Work = cvar.st_Work


def get_auto_display(*args):
    r"""get_auto_display(auto_display)"""
    return _ida_auto.get_auto_display(*args)

def show_auto(*args):
    r"""show_auto(ea, type=AU_NONE)"""
    return _ida_auto.show_auto(*args)

def show_addr(*args):
    r"""show_addr(ea)"""
    return _ida_auto.show_addr(*args)

def set_ida_state(*args):
    r"""set_ida_state(st) -> idastate_t"""
    return _ida_auto.set_ida_state(*args)

def may_create_stkvars(*args):
    r"""may_create_stkvars() -> bool"""
    return _ida_auto.may_create_stkvars(*args)

def may_trace_sp(*args):
    r"""may_trace_sp() -> bool"""
    return _ida_auto.may_trace_sp(*args)

def auto_mark_range(*args):
    r"""auto_mark_range(start, end, type)"""
    return _ida_auto.auto_mark_range(*args)

def auto_mark(*args):
    r"""auto_mark(ea, type)"""
    return _ida_auto.auto_mark(*args)

def auto_unmark(*args):
    r"""auto_unmark(start, end, type)"""
    return _ida_auto.auto_unmark(*args)

def plan_ea(*args):
    r"""plan_ea(ea)"""
    return _ida_auto.plan_ea(*args)

def plan_range(*args):
    r"""plan_range(sEA, eEA)"""
    return _ida_auto.plan_range(*args)

def auto_make_code(*args):
    r"""auto_make_code(ea)"""
    return _ida_auto.auto_make_code(*args)

def auto_make_proc(*args):
    r"""auto_make_proc(ea)"""
    return _ida_auto.auto_make_proc(*args)

def reanalyze_callers(*args):
    r"""reanalyze_callers(ea, noret)"""
    return _ida_auto.reanalyze_callers(*args)

def revert_ida_decisions(*args):
    r"""revert_ida_decisions(ea1, ea2)"""
    return _ida_auto.revert_ida_decisions(*args)

def auto_apply_type(*args):
    r"""auto_apply_type(caller, callee)"""
    return _ida_auto.auto_apply_type(*args)

def auto_apply_tail(*args):
    r"""auto_apply_tail(tail_ea, parent_ea)"""
    return _ida_auto.auto_apply_tail(*args)

def plan_and_wait(*args):
    r"""plan_and_wait(ea1, ea2, final_pass=True) -> int"""
    return _ida_auto.plan_and_wait(*args)

def auto_wait(*args):
    r"""auto_wait() -> bool"""
    return _ida_auto.auto_wait(*args)

def auto_cancel(*args):
    r"""auto_cancel(ea1, ea2)"""
    return _ida_auto.auto_cancel(*args)

def auto_is_ok(*args):
    r"""auto_is_ok() -> bool"""
    return _ida_auto.auto_is_ok(*args)

def peek_auto_queue(*args):
    r"""peek_auto_queue(low_ea, type) -> ea_t"""
    return _ida_auto.peek_auto_queue(*args)

def auto_get(*args):
    r"""auto_get(type, lowEA, highEA) -> ea_t"""
    return _ida_auto.auto_get(*args)

def auto_recreate_insn(*args):
    r"""auto_recreate_insn(ea) -> int"""
    return _ida_auto.auto_recreate_insn(*args)

def is_auto_enabled(*args):
    r"""is_auto_enabled() -> bool"""
    return _ida_auto.is_auto_enabled(*args)

def enable_auto(*args):
    r"""enable_auto(enable) -> bool"""
    return _ida_auto.enable_auto(*args)

if _BC695:
    analyze_area = plan_and_wait
    autoCancel = auto_cancel
    autoIsOk = auto_is_ok
    autoMark = auto_mark
    autoUnmark = auto_unmark
    autoWait = auto_wait
    noUsed = plan_ea
    setStat = set_ida_state
    showAddr = show_addr
    showAuto = show_auto




