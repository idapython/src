# This file was automatically generated by SWIG (http://www.swig.org).
# Version 4.0.1
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.

"""IDA Plugin SDK API wrapper: fpro"""

from sys import version_info as _swig_python_version_info
if _swig_python_version_info < (2, 7, 0):
    raise RuntimeError("Python 2.7 or later required")

# Import the low-level C/C++ module
if __package__ or "." in __name__:
    from . import _ida_fpro
else:
    import _ida_fpro

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

class qfile_t(object):
    r"""Proxy of C++ qfile_t class."""

    thisown = property(lambda x: x.this.own(), lambda x, v: x.this.own(v), doc="The membership flag")
    __repr__ = _swig_repr
    __idc_cvt_id__ = property(_ida_fpro.qfile_t___idc_cvt_id___get, _ida_fpro.qfile_t___idc_cvt_id___set, doc=r"""__idc_cvt_id__""")

    def __init__(self, *args):
        r"""
        __init__(self, rhs) -> qfile_t
        __init__(self, pycobject=None) -> qfile_t
        """
        _ida_fpro.qfile_t_swiginit(self, _ida_fpro.new_qfile_t(*args))

    def opened(self, *args):
        r"""opened(self) -> bool"""
        return _ida_fpro.qfile_t_opened(self, *args)

    def close(self, *args):
        r"""close(self)"""
        return _ida_fpro.qfile_t_close(self, *args)
    __swig_destroy__ = _ida_fpro.delete_qfile_t

    def open(self, *args):
        r"""open(self, filename, mode) -> bool"""
        return _ida_fpro.qfile_t_open(self, *args)

    @staticmethod
    def from_fp(*args):
        r"""from_fp(fp) -> qfile_t"""
        return _ida_fpro.qfile_t_from_fp(*args)

    @staticmethod
    def from_cobject(*args):
        r"""from_cobject(pycobject) -> qfile_t"""
        return _ida_fpro.qfile_t_from_cobject(*args)

    @staticmethod
    def tmpfile(*args):
        r"""tmpfile() -> qfile_t"""
        return _ida_fpro.qfile_t_tmpfile(*args)

    def get_fp(self, *args):
        r"""get_fp(self) -> FILE *"""
        return _ida_fpro.qfile_t_get_fp(self, *args)

    def seek(self, *args):
        r"""seek(self, offset, whence=SEEK_SET) -> int"""
        return _ida_fpro.qfile_t_seek(self, *args)

    def tell(self, *args):
        r"""tell(self) -> int64"""
        return _ida_fpro.qfile_t_tell(self, *args)

    def readbytes(self, *args):
        r"""readbytes(self, size, big_endian) -> PyObject *"""
        return _ida_fpro.qfile_t_readbytes(self, *args)

    def read(self, *args):
        r"""read(self, size) -> PyObject *"""
        return _ida_fpro.qfile_t_read(self, *args)

    def gets(self, *args):
        r"""gets(self, size) -> PyObject *"""
        return _ida_fpro.qfile_t_gets(self, *args)

    def writebytes(self, *args):
        r"""writebytes(self, py_buf, big_endian) -> int"""
        return _ida_fpro.qfile_t_writebytes(self, *args)

    def write(self, *args):
        r"""write(self, py_buf) -> int"""
        return _ida_fpro.qfile_t_write(self, *args)

    def puts(self, *args):
        r"""puts(self, str) -> int"""
        return _ida_fpro.qfile_t_puts(self, *args)

    def size(self, *args):
        r"""size(self) -> int64"""
        return _ida_fpro.qfile_t_size(self, *args)

    def flush(self, *args):
        r"""flush(self) -> int"""
        return _ida_fpro.qfile_t_flush(self, *args)

    def filename(self, *args):
        r"""filename(self) -> PyObject *"""
        return _ida_fpro.qfile_t_filename(self, *args)

    def get_char(self, *args):
        r"""get_char(self) -> PyObject *"""
        return _ida_fpro.qfile_t_get_char(self, *args)

    def put_char(self, *args):
        r"""put_char(self, chr) -> int"""
        return _ida_fpro.qfile_t_put_char(self, *args)

# Register qfile_t in _ida_fpro:
_ida_fpro.qfile_t_swigregister(qfile_t)

def qfile_t_from_fp(*args):
    r"""qfile_t_from_fp(fp) -> qfile_t"""
    return _ida_fpro.qfile_t_from_fp(*args)

def qfile_t_from_cobject(*args):
    r"""qfile_t_from_cobject(pycobject) -> qfile_t"""
    return _ida_fpro.qfile_t_from_cobject(*args)

def qfile_t_tmpfile(*args):
    r"""qfile_t_tmpfile() -> qfile_t"""
    return _ida_fpro.qfile_t_tmpfile(*args)



