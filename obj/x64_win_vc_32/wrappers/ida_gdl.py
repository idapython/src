# This file was automatically generated by SWIG (http://www.swig.org).
# Version 4.0.1
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.

"""IDA Plugin SDK API wrapper: gdl"""

from sys import version_info as _swig_python_version_info
if _swig_python_version_info < (2, 7, 0):
    raise RuntimeError("Python 2.7 or later required")

# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_gdl
else:
    import _ida_gdl

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
fcb_normal = _ida_gdl.fcb_normal

fcb_indjump = _ida_gdl.fcb_indjump

fcb_ret = _ida_gdl.fcb_ret

fcb_cndret = _ida_gdl.fcb_cndret

fcb_noret = _ida_gdl.fcb_noret

fcb_enoret = _ida_gdl.fcb_enoret

fcb_extern = _ida_gdl.fcb_extern

fcb_error = _ida_gdl.fcb_error

class node_iterator(object):
    r"""Proxy of C++ node_iterator class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""__init__(self, _g, n) -> node_iterator"""
        _ida_gdl.node_iterator_swiginit(self, _ida_gdl.new_node_iterator(*args))

    def __eq__(self, *args):
        r"""__eq__(self, n) -> bool"""
        return _ida_gdl.node_iterator___eq__(self, *args)

    def __ne__(self, *args):
        r"""__ne__(self, n) -> bool"""
        return _ida_gdl.node_iterator___ne__(self, *args)

    def __ref__(self, *args):
        r"""__ref__(self) -> int"""
        return _ida_gdl.node_iterator___ref__(self, *args)
    __swig_destroy__ = _ida_gdl.delete_node_iterator

# Register node_iterator in _ida_gdl:
_ida_gdl.node_iterator_swigregister(node_iterator)


def gen_gdl(*args):
    r"""gen_gdl(g, fname)"""
    return _ida_gdl.gen_gdl(*args)

def display_gdl(*args):
    r"""display_gdl(fname) -> int"""
    return _ida_gdl.display_gdl(*args)

def gen_flow_graph(*args):
    r"""gen_flow_graph(filename, title, pfn, ea1, ea2, gflags) -> bool"""
    return _ida_gdl.gen_flow_graph(*args)
CHART_PRINT_NAMES = _ida_gdl.CHART_PRINT_NAMES

CHART_GEN_DOT = _ida_gdl.CHART_GEN_DOT

CHART_GEN_GDL = _ida_gdl.CHART_GEN_GDL

CHART_WINGRAPH = _ida_gdl.CHART_WINGRAPH


def gen_simple_call_chart(*args):
    r"""gen_simple_call_chart(filename, wait, title, gflags) -> bool"""
    return _ida_gdl.gen_simple_call_chart(*args)

def gen_complex_call_chart(*args):
    r"""gen_complex_call_chart(filename, wait, title, ea1, ea2, flags, recursion_depth=-1) -> bool"""
    return _ida_gdl.gen_complex_call_chart(*args)
CHART_NOLIBFUNCS = _ida_gdl.CHART_NOLIBFUNCS

CHART_REFERENCING = _ida_gdl.CHART_REFERENCING

CHART_REFERENCED = _ida_gdl.CHART_REFERENCED

CHART_RECURSIVE = _ida_gdl.CHART_RECURSIVE

CHART_FOLLOW_DIRECTION = _ida_gdl.CHART_FOLLOW_DIRECTION

CHART_IGNORE_XTRN = _ida_gdl.CHART_IGNORE_XTRN

CHART_IGNORE_DATA_BSS = _ida_gdl.CHART_IGNORE_DATA_BSS

CHART_IGNORE_LIB_TO = _ida_gdl.CHART_IGNORE_LIB_TO

CHART_IGNORE_LIB_FROM = _ida_gdl.CHART_IGNORE_LIB_FROM

CHART_PRINT_COMMENTS = _ida_gdl.CHART_PRINT_COMMENTS

CHART_PRINT_DOTS = _ida_gdl.CHART_PRINT_DOTS

class qbasic_block_t(ida_range.range_t):
    r"""Proxy of C++ qbasic_block_t class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr

    def __init__(self, *args):
        r"""__init__(self) -> qbasic_block_t"""
        _ida_gdl.qbasic_block_t_swiginit(self, _ida_gdl.new_qbasic_block_t(*args))
    __swig_destroy__ = _ida_gdl.delete_qbasic_block_t

# Register qbasic_block_t in _ida_gdl:
_ida_gdl.qbasic_block_t_swigregister(qbasic_block_t)


def is_noret_block(*args):
    r"""is_noret_block(btype) -> bool"""
    return _ida_gdl.is_noret_block(*args)

def is_ret_block(*args):
    r"""is_ret_block(btype) -> bool"""
    return _ida_gdl.is_ret_block(*args)
FC_PRINT = _ida_gdl.FC_PRINT

FC_NOEXT = _ida_gdl.FC_NOEXT

FC_PREDS = _ida_gdl.FC_PREDS

FC_APPND = _ida_gdl.FC_APPND

FC_CHKBREAK = _ida_gdl.FC_CHKBREAK

class qflow_chart_t(object):
    r"""Proxy of C++ qflow_chart_t class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    title = property(_ida_gdl.qflow_chart_t_title_get, _ida_gdl.qflow_chart_t_title_set, doc=r"""title""")
    bounds = property(_ida_gdl.qflow_chart_t_bounds_get, _ida_gdl.qflow_chart_t_bounds_set, doc=r"""bounds""")
    pfn = property(_ida_gdl.qflow_chart_t_pfn_get, _ida_gdl.qflow_chart_t_pfn_set, doc=r"""pfn""")
    flags = property(_ida_gdl.qflow_chart_t_flags_get, _ida_gdl.qflow_chart_t_flags_set, doc=r"""flags""")
    nproper = property(_ida_gdl.qflow_chart_t_nproper_get, _ida_gdl.qflow_chart_t_nproper_set, doc=r"""nproper""")

    def __init__(self, *args):
        r"""
        __init__(self) -> qflow_chart_t
        __init__(self, _title, _pfn, _ea1, _ea2, _flags) -> qflow_chart_t
        """
        _ida_gdl.qflow_chart_t_swiginit(self, _ida_gdl.new_qflow_chart_t(*args))

    def create(self, *args):
        r"""
        create(self, _title, _pfn, _ea1, _ea2, _flags)
        create(self, _title, ranges, _flags)
        """
        return _ida_gdl.qflow_chart_t_create(self, *args)

    def append_to_flowchart(self, *args):
        r"""append_to_flowchart(self, ea1, ea2)"""
        return _ida_gdl.qflow_chart_t_append_to_flowchart(self, *args)

    def refresh(self, *args):
        r"""refresh(self)"""
        return _ida_gdl.qflow_chart_t_refresh(self, *args)

    def calc_block_type(self, *args):
        r"""calc_block_type(self, blknum) -> fc_block_type_t"""
        return _ida_gdl.qflow_chart_t_calc_block_type(self, *args)

    def is_ret_block(self, *args):
        r"""is_ret_block(self, blknum) -> bool"""
        return _ida_gdl.qflow_chart_t_is_ret_block(self, *args)

    def is_noret_block(self, *args):
        r"""is_noret_block(self, blknum) -> bool"""
        return _ida_gdl.qflow_chart_t_is_noret_block(self, *args)

    def print_node_attributes(self, *args):
        r"""print_node_attributes(self, arg2, arg3)"""
        return _ida_gdl.qflow_chart_t_print_node_attributes(self, *args)

    def nsucc(self, *args):
        r"""nsucc(self, node) -> int"""
        return _ida_gdl.qflow_chart_t_nsucc(self, *args)

    def npred(self, *args):
        r"""npred(self, node) -> int"""
        return _ida_gdl.qflow_chart_t_npred(self, *args)

    def succ(self, *args):
        r"""succ(self, node, i) -> int"""
        return _ida_gdl.qflow_chart_t_succ(self, *args)

    def pred(self, *args):
        r"""pred(self, node, i) -> int"""
        return _ida_gdl.qflow_chart_t_pred(self, *args)

    def print_names(self, *args):
        r"""print_names(self) -> bool"""
        return _ida_gdl.qflow_chart_t_print_names(self, *args)

    def get_node_label(self, *args):
        r"""get_node_label(self, arg2, arg3, arg4) -> char *"""
        return _ida_gdl.qflow_chart_t_get_node_label(self, *args)

    def size(self, *args):
        r"""size(self) -> int"""
        return _ida_gdl.qflow_chart_t_size(self, *args)

    def __getitem__(self, *args):
        r"""__getitem__(self, n) -> qbasic_block_t"""
        return _ida_gdl.qflow_chart_t___getitem__(self, *args)
    __swig_destroy__ = _ida_gdl.delete_qflow_chart_t

# Register qflow_chart_t in _ida_gdl:
_ida_gdl.qflow_chart_t_swigregister(qflow_chart_t)


#<pycode(py_gdl)>
import _ida_idaapi
import types
# -----------------------------------------------------------------------
class BasicBlock(object):
    """Basic block class. It is returned by the Flowchart class"""
    def __init__(self, id, bb, fc):
        self._fc = fc

        self.id = id
        """Basic block ID"""

        self.start_ea = bb.start_ea
        """start_ea of basic block"""

        self.end_ea = bb.end_ea
        """end_ea of basic block"""

        self.type  = self._fc._q.calc_block_type(self.id)
        """Block type (check fc_block_type_t enum)"""


    def preds(self):
        """
        Iterates the predecessors list
        """
        q = self._fc._q
        for i in xrange(0, self._fc._q.npred(self.id)):
            yield self._fc[q.pred(self.id, i)]


    def succs(self):
        """
        Iterates the successors list
        """
        q = self._fc._q
        for i in xrange(0, q.nsucc(self.id)):
            yield self._fc[q.succ(self.id, i)]

    try:
        if _BC695:
            startEA = property(lambda self: self.start_ea, lambda self, ea: setattr(self, "start_ea", ea))
            endEA = property(lambda self: self.end_ea, lambda self, ea: setattr(self, "end_ea", ea))
    except:
        pass # BC695 not defined at compile-time

# -----------------------------------------------------------------------
class FlowChart(object):
    """
    Flowchart class used to determine basic blocks.
    Check ex_gdl_qflow_chart.py for sample usage.
    """
    def __init__(self, f=None, bounds=None, flags=0):
        """
        Constructor
        @param f: A func_t type, use get_func(ea) to get a reference
        @param bounds: A tuple of the form (start, end). Used if "f" is None
        @param flags: one of the FC_xxxx flags. One interesting flag is FC_PREDS
        """
        if (f is None) and (bounds is None or type(bounds) != tuple):
            raise Exception("Please specifiy either a function or start/end pair")

        if bounds is None:
            bounds = (_ida_idaapi.BADADDR, _ida_idaapi.BADADDR)

# Create the flowchart
        self._q = qflow_chart_t("", f, bounds[0], bounds[1], flags)

    size = property(lambda self: self._q.size())
    """Number of blocks in the flow chart"""


    def refresh(self):
        """Refreshes the flow chart"""
        self._q.refresh()


    def _getitem(self, index):
        return BasicBlock(index, self._q[index], self)


    def __iter__(self):
        return (self._getitem(index) for index in xrange(0, self.size))


    def __getitem__(self, index):
        """
        Returns a basic block

        @return: BasicBlock
        """
        if index >= self.size:
            raise KeyError
        else:
            return self._getitem(index)

#</pycode(py_gdl)>



