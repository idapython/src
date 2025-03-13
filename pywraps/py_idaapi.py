from __future__ import print_function
from __future__ import annotations
# -----------------------------------------------------------------------
try:
    import pywraps
    pywraps_there = True
except:
    pywraps_there = False

import _ida_idaapi
import random
import operator
import datetime

#<pycode(py_idaapi)>

# Type aliases (we currently still support 3.8, so no `type` statement, or `typing.TypeAlias`es just yet)
ea_t = int

__EA64__ = BADADDR == 0xFFFFFFFFFFFFFFFF

import inspect
import struct
import traceback
import os
import sys
import bisect
try:
    import __builtin__ as builtins
    # This basically mimics six's features (it's not ok to ask the IDAPython runtime to rely on six)
    integer_types = (int, long)
    string_types = (str, unicode)
    long_type = long
except:
    import builtins
    integer_types = (int,)
    string_types = (str,)
    long_type = int
import re

def require(modulename, package=None):
    """
    Load, or reload a module.

    When under heavy development, a user's tool might consist of multiple
    modules. If those are imported using the standard 'import' mechanism,
    there is no guarantee that the Python implementation will re-read
    and re-evaluate the module's Python code. In fact, it usually doesn't.
    What should be done instead is 'reload()'-ing that module.

    This is a simple helper function that will do just that: In case the
    module doesn't exist, it 'import's it, and if it does exist,
    'reload()'s it.

    The importing module (i.e., the module calling require()) will have
    the loaded module bound to its globals(), under the name 'modulename'.
    (If require() is called from the command line, the importing module
    will be '__main__'.)

    For more information, see: <http://www.hexblog.com/?p=749>.
    """
    import inspect
    frame_obj, filename, line_number, function_name, lines, index = inspect.stack()[1]
    importer_module = inspect.getmodule(frame_obj)
    if importer_module is None: # No importer module; called from command line
        importer_module = sys.modules['__main__']
    if modulename in sys.modules.keys():
        m = sys.modules[modulename]
        if sys.version_info.major >= 3:
            import importlib
            importlib.reload(m)
        else:
            reload(m)
        m = sys.modules[modulename]
    else:
        import importlib
        m = importlib.import_module(modulename, package)
        sys.modules[modulename] = m
    setattr(importer_module, modulename, m)

def _replace_module_function(replacement):
    name = replacement.__name__
    modname = replacement.__module__
    assert(name)
    assert(modname)
    mod = sys.modules[modname]
    orig = getattr(mod, name)
    replacement.__doc__ = orig.__doc__
    replacement.__name__ = name
    replacement.__dict__["orig"] = orig
    setattr(mod, name, replacement)

def replfun(func):
    _replace_module_function(func)
    return func


# -----------------------------------------------------------------------

# Seek constants
SEEK_SET = 0 # from the file start
SEEK_CUR = 1 # from the current position
SEEK_END = 2 # from the file end

# Plugin constants
PLUGIN_MOD   = 0x0001
PLUGIN_DRAW  = 0x0002
PLUGIN_SEG   = 0x0004
PLUGIN_UNL   = 0x0008
PLUGIN_HIDE  = 0x0010
PLUGIN_DBG   = 0x0020
PLUGIN_PROC  = 0x0040
PLUGIN_FIX   = 0x0080
PLUGIN_MULTI = 0x0100
PLUGIN_SKIP  = 0
PLUGIN_OK    = 1
PLUGIN_KEEP  = 2

# PyIdc conversion object IDs
PY_ICID_INT64  = 0
"""int64 object"""
PY_ICID_BYREF  = 1
"""byref object"""
PY_ICID_OPAQUE = 2
"""opaque object"""

# Step trace options (used with set_step_trace_options())
ST_OVER_DEBUG_SEG  = 0x01
"""step tracing will be disabled when IP is in a debugger segment"""

ST_OVER_LIB_FUNC    = 0x02
"""step tracing will be disabled when IP is in a library function"""

# -----------------------------------------------------------------------
class pyidc_opaque_object_t(object):
    """This is the base class for all Python<->IDC opaque objects"""
    __idc_cvt_id__ = PY_ICID_OPAQUE

# -----------------------------------------------------------------------
class py_clinked_object_t(pyidc_opaque_object_t):
    """
    This is a utility and base class for C linked objects
    """
    def __init__(self, lnk = None):
        # static link: if a link was provided
        self.__static_clink__ = True if lnk else False

        # Create link if it was not provided
        self.__clink__ = lnk if lnk else self._create_clink()

    def __del__(self):
        """Delete the link upon object destruction (only if not static)"""
        self._free()

    def _free(self):
        """Explicitly delete the link (only if not static)"""
        if not self.__static_clink__ and self.__clink__ is not None:
            self._del_clink(self.__clink__)
            self.__clink__ = None

    def copy(self):
        """Returns a new copy of this class"""

        # Create an unlinked instance
        inst = self.__class__()

        # Assign self to the new instance
        inst.assign(self)

        return inst

    #
    # Methods to be overwritten
    #
    def _create_clink(self):
        """
        Overwrite me.
        Creates a new clink
        @return: PyCapsule representing the C link
        """
        pass

    def _del_clink(self, lnk):
        """
        Overwrite me.
        This method deletes the link
        """
        pass

    def _get_clink_ptr(self):
        """
        Overwrite me.
        Returns the C link pointer as a 64bit number
        """
        pass

    def assign(self, other):
        """
        Overwrite me.
        This method allows you to assign an instance contents to anothers
        @return: Boolean
        """
        pass

    clink = property(lambda self: self.__clink__)
    """Returns the C link as a PyObject"""

    clink_ptr = property(lambda self: self._get_clink_ptr())
    """Returns the C link pointer as a number"""

# -----------------------------------------------------------------------
class object_t(object):
    """Helper class used to initialize empty objects"""
    def __init__(self, **kwds):
        self.__dict__ = kwds

    def __getitem__(self, idx):
        """Allow access to object attributes by index (like dictionaries)"""
        return getattr(self, idx)

# -----------------------------------------------------------------------
def _qvector_front(self):
    return self.at(0)

# -----------------------------------------------------------------------
def _qvector_back(self):
    return self.at((self.size() - 1) if self.size() else 0)

# -----------------------------------------------------------------------
def _bounded_getitem_iterator(self):
    """Helper function, to be set as __iter__ method for qvector-, or array-based classes."""
    for i in range(len(self)):
        yield self[i]

# -----------------------------------------------------------------------
class plugin_t(pyidc_opaque_object_t):
    """Base class for all scripted plugins."""
    def run(self, arg): pass
    def term(self): pass

# -----------------------------------------------------------------------
class plugmod_t(pyidc_opaque_object_t):
    """Base class for all scripted multi-plugins."""
    pass

# -----------------------------------------------------------------------
class pyidc_cvt_helper__(object):
    """
    This is a special helper object that helps detect which kind
    of object is this python object wrapping and how to convert it
    back and from IDC.
    This object is characterized by its special attribute and its value
    """
    def __init__(self, cvt_id, value):
        self.__idc_cvt_id__ = cvt_id
        self.value = value

    def __set_value(self, v):
        self.__idc_cvt_value__ = v
    def __get_value(self):
        return self.__idc_cvt_value__
    value = property(__get_value, __set_value)

# -----------------------------------------------------------------------
class PyIdc_cvt_int64__(pyidc_cvt_helper__):
    """Helper class for explicitly representing VT_INT64 values"""

    def __init__(self, v):
        # id = 0 = int64 object
        super(self.__class__, self).__init__(PY_ICID_INT64, v)

    # operation table
    __op_table = \
    {
        0: lambda a, b: a + b,
        1: lambda a, b: a - b,
        2: lambda a, b: a * b,
        3: lambda a, b: a / b
    }
    # carries the operation given its number
    def __op(self, op_n, other, rev=False):
        a = self.value
        # other operand of same type? then take its value field
        if type(other) == type(self):
            b = other.value
        else:
            b = other
        if rev:
            t = a
            a = b
            b = t
        # construct a new object and return as the result
        return self.__class__(self.__op_table[op_n](a, b))

    # overloaded operators
    def __add__(self, other):  return self.__op(0, other)
    def __sub__(self, other):  return self.__op(1, other)
    def __mul__(self, other):  return self.__op(2, other)
    def __div__(self, other):  return self.__op(3, other)
    def __radd__(self, other): return self.__op(0, other, True)
    def __rsub__(self, other): return self.__op(1, other, True)
    def __rmul__(self, other): return self.__op(2, other, True)
    def __rdiv__(self, other): return self.__op(3, other, True)

# -----------------------------------------------------------------------
class PyIdc_cvt_refclass__(pyidc_cvt_helper__):
    """Helper class for representing references to immutable objects"""
    def __init__(self, v):
        # id = one = byref object
        super(self.__class__, self).__init__(PY_ICID_BYREF, v)

    def cstr(self):
        """Returns the string as a C string (up to the zero termination)"""
        return as_cstr(self.value)

# -----------------------------------------------------------------------
def as_cstr(val):
    """
    Returns a C str from the passed value. The passed value can be of type refclass (returned by a call to buffer() or byref())
    It scans for the first \\x00 and returns the string value up to that point.
    """
    if isinstance(val, PyIdc_cvt_refclass__):
        val = val.value

    n = val.find('\x00')
    return val if n == -1 else val[:n]

# -----------------------------------------------------------------------
def as_UTF16(s):
    """Convenience function to convert a string into appropriate unicode format"""
    # use UTF16 big/little endian, depending on the environment?
    import _ida_ida
    if sys.version_info.major >= 3:
        if type(s) == bytes:
            s = s.decode("UTF-8")
    else:
        s = unicode(s)
    return s.encode("UTF-16" + ("BE" if _ida_ida.inf_is_be() else "LE"))
as_unicode = as_UTF16

# -----------------------------------------------------------------------
def as_uint32(v):
    """Returns a number as an unsigned int32 number"""
    return v & 0xffffffff

# -----------------------------------------------------------------------
def as_int32(v):
    """Returns a number as a signed int32 number"""
    return as_signed(v, 32)

# -----------------------------------------------------------------------
def as_signed(v, nbits = 32):
    """
    Returns a number as signed. The number of bits are specified by the user.
    The MSB holds the sign.
    """
    return -(( ~v & ((1 << nbits)-1) ) + 1) if v & (1 << nbits-1) else v & ((1 << nbits)-1)

# ----------------------------------------------------------------------
def TRUNC(ea):
    """ Truncate EA for the current application bitness"""
    import _ida_ida
    return (ea & 0xFFFFFFFFFFFFFFFF) if _ida_ida.inf_is_64bit() else (ea & 0xFFFFFFFF)

# ----------------------------------------------------------------------
def copy_bits(v, s, e=-1):
    """
    Copy bits from a value
    @param v: the value
    @param s: starting bit (0-based)
    @param e: ending bit
    """
    # end-bit not specified? use start bit (thus extract one bit)
    if e == -1:
        e = s
    # swap start and end if start > end
    if s > e:
        e, s = s, e

    mask = ~(((1 << (e-s+1))-1) << s)

    return (v & mask) >> s

# ----------------------------------------------------------------------
__struct_unpack_table = {
  1: ('b', 'B'),
  2: ('h', 'H'),
  4: ('l', 'L'),
  8: ('q', 'Q')
}

# ----------------------------------------------------------------------
def struct_unpack(buffer, signed = False, offs = 0):
    """
    Unpack a buffer given its length and offset using struct.unpack_from().
    This function will know how to unpack the given buffer by using the lookup table '__struct_unpack_table'
    If the buffer is of unknown length then None is returned. Otherwise the unpacked value is returned.
    """
    # Supported length?
    n = len(buffer)
    if n not in __struct_unpack_table:
        return None
    # Conver to number
    signed = 1 if signed else 0

    # Unpack
    return struct.unpack_from(__struct_unpack_table[n][signed], buffer, offs)[0]

# ------------------------------------------------------------
def IDAPython_ExecSystem(cmd):
    """
    Executes a command with popen().
    """
    try:
        f = os.popen(cmd, "r")
        s = ''.join(f.readlines())
        f.close()
        return s
    except Exception as e:
        return "%s\n%s" % (str(e), traceback.format_exc())

# ------------------------------------------------------------
def IDAPython_FormatExc(etype, value=None, tb=None, limit=None):
    """
    This function is used to format an exception given the
    values returned by a PyErr_Fetch()
    """
    import traceback
    try:
        return ''.join(traceback.format_exception(etype, value, tb, limit))
    except:
        parts = [str(value)]
        if tb:
            try:
                parts.append("".join(traceback.format_tb(tb)))
            finally:
                pass
        return "\n".join(parts)


# ------------------------------------------------------------
def IDAPython_ExecScript(path, g, print_error=True):
    """
    Run the specified script.

    This function is used by the low-level plugin code.
    """
    path_dir = os.path.dirname(path)
    if len(path_dir) and path_dir not in sys.path:
        sys.path.append(path_dir)

    argv = sys.argv
    sys.argv = [path]

    # Adjust the __file__ path in the globals we pass to the script
    FILE_ATTR = "__file__"
    has__file__ = FILE_ATTR in g
    if has__file__:
        old__file__ = g[FILE_ATTR]
    g[FILE_ATTR] = path

    try:
        if sys.version_info.major >= 3:
            with open(path, "rb") as fin:
                raw = fin.read()
            encoding = "UTF-8" # UTF-8 by default: https://www.python.org/dev/peps/pep-3120/

            # Look for a 'coding' comment
            encoding_pat = re.compile(r'\s*#.*coding[:=]\s*([-\w.]+).*')
            for line in raw.decode("ASCII", errors='replace').split("\n"):
                match = encoding_pat.match(line)
                if match:
                    encoding = match.group(1)
                    break

            code = compile(raw.decode(encoding), path, 'exec')
            exec(code, g)
        else:
            execfile(path, g)
        PY_COMPILE_ERR = None
    except Exception as e:
        PY_COMPILE_ERR = "%s\n%s" % (str(e), traceback.format_exc())
        if print_error:
            print(PY_COMPILE_ERR)
    finally:
        # Restore state
        if has__file__:
            g[FILE_ATTR] = old__file__
        else:
            del g[FILE_ATTR]
        sys.argv = argv

    return PY_COMPILE_ERR

# ------------------------------------------------------------
def IDAPython_LoadProcMod(path, g, print_error=True):
    """
    Load processor module.
    """
    pname = g['__name__'] if g and "__name__" in g else '__main__'
    parent = sys.modules[pname]
    path_dir, path_fname = os.path.split(path)
    procmod_name = os.path.splitext(path_fname)[0]
    procobj = None
    fp = None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(procmod_name, path)
        procmod = importlib.util.module_from_spec(spec)
        sys.modules[procmod_name] = procmod
        spec.loader.exec_module(procmod)
        if parent:
            setattr(parent, procmod_name, procmod)
            # export attrs from parent to processor module
            parent_attrs = getattr(parent, '__all__',
                                   (attr for attr in dir(parent) if not attr.startswith('_')))
            for pa in parent_attrs:
                setattr(procmod, pa, getattr(parent, pa))
            # instantiate processor object
            if getattr(procmod, 'PROCESSOR_ENTRY', None):
                procobj = procmod.PROCESSOR_ENTRY()
        PY_COMPILE_ERR = None
    except Exception as e:
        PY_COMPILE_ERR = "%s\n%s" % (str(e), traceback.format_exc())
        if print_error:
            print(PY_COMPILE_ERR)

    return (PY_COMPILE_ERR, procobj)

# ------------------------------------------------------------
def IDAPython_UnLoadProcMod(script, g, print_error=True):
    """
    Unload processor module.
    """
    pname = g['__name__'] if g and "__name__" in g else '__main__'
    parent = sys.modules[pname]

    script_fname = os.path.split(script)[1]
    procmod_name = os.path.splitext(script_fname)[0]
    if getattr(parent, procmod_name, None):
        delattr(parent, procmod_name)
        del sys.modules[procmod_name]
    PY_COMPILE_ERR = None
    return PY_COMPILE_ERR

# ----------------------------------------------------------------------
# Shameless rip-off of pdoc AST parsing follows
def IDAPython_GetDocstrings(obj):
    import ast
    from itertools import tee
    from itertools import zip_longest
    from typing import TypeVar
    from typing import Optional
    T = TypeVar("T")

    empty: type = inspect.Signature.empty  # type: ignore  # noqa

    if sys.version_info >= (3, 9):
        from functools import cache
    else:  # pragma: no cover
        from functools import lru_cache

        cache = lru_cache(maxsize=None)

    if sys.version_info >= (3, 12):
        from ast import TypeAlias as ast_TypeAlias
    else:  # pragma: no cover
        class ast_TypeAlias:
            pass

    def _dedent(source: str) -> str:
        if not source or source[0] not in (" ", "\t"):
            return source
        source = source.lstrip()
        if not any(source.startswith(x) for x in ["async ", "def ", "class "]):
            first_line, rest = source.split("\n", 1)
            return first_line + "\n" + _dedent(rest)
        else:
            return source

    def _pairwise_longest(iterable):
        """s -> (s0,s1), (s1,s2), (s2, s3),  ..., (sN, None)"""
        a, b = tee(iterable)
        next(b, None)
        return zip_longest(a, b)

    @cache
    def _nodes(tree):
        """
        Returns the list of all nodes in tree's body.
        """
        return list(_nodes_iter(tree))

    def _nodes_iter(tree):
        for a in tree.body:
            yield a

    @cache
    def _walk_tree(tree):
        var_docstrings = {}
        func_docstrings = {}
        nodes = _nodes(tree)
        if len(nodes) == 1 and type(nodes[0]) is ast.ClassDef:
            nodes = nodes[0].body
        for a, b in _pairwise_longest(nodes):
            if isinstance(a, ast_TypeAlias):
                name = a.name.id
            elif (
                isinstance(a, ast.AnnAssign) and isinstance(a.target, ast.Name) and a.simple
            ):
                name = a.target.id
            elif (
                isinstance(a, ast.Assign)
                and len(a.targets) == 1
                and isinstance(a.targets[0], ast.Name)
            ):
                name = a.targets[0].id
            elif isinstance(a, ast.FunctionDef) and a.body:
                continue
            else:
                continue
            if (
                isinstance(b, ast.Expr)
                and isinstance(b.value, ast.Constant)
                and isinstance(b.value.value, str)
            ):
                var_docstrings[name] = inspect.cleandoc(b.value.value).strip()
        return var_docstrings

    res = None
    try:
        res = _walk_tree(ast.parse(inspect.getsource(obj)))
    except:
        pass
    return res

# ----------------------------------------------------------------------
class __IDAPython_Completion_Util(object):
    """Internal utility class for auto-completion support"""
    def __init__(self):
        pass

    def __resolve_type(self, tname):
        rtypes = {
            'char': 'char',
            'short': 'short',
            'int': 'int',
            'long': 'long',
            'long long': 'long long',
            'unsigned char': 'unsigned char',
            'unsigned short': 'unsigned short',
            'unsigned int': 'unsigned int',
            'unsigned long': 'unsigned long',
            'unsigned long long': 'unsigned long long',
            'aflags_t': 'unsigned int',
            'off_t': 'unsigned long long',
            'time_t': 'unsigned long long',
            'size_t': 'unsigned long',
            'uint_fast8_t': 'unsigned char',
            'uint_fast16_t': 'unsigned long',
            'uint_fast32_t': 'unsigned long',
            'uint_fast64_t': 'unsigned long',
            'uintptr_t': 'unsigned long',
            'wint_t': 'unsigned int',
            '__cpu_mask': 'unsigned long',
            '_Atomic_word': 'int',
            'uchar': 'unsigned char',
            'ushort': 'unsigned short',
            'uint': 'unsigned int',
            'int8': 'char',
            'uint8': 'unsigned char',
            'int16': 'short',
            'uint16': 'unsigned short',
            'int32': 'int',
            'uint32': 'unsigned int',
            'uint64': 'unsigned long long',
            'int64': 'long long',
            'ulonglong': 'unsigned long long',
            'longlong': 'long long',
            'wchar16_t': 'unsigned short',
            'wchar32_t': 'unsigned int',
            'ea_t': 'unsigned long long',
            'sel_t': 'unsigned long long',
            'asize_t': 'unsigned long long',
            'adiff_t': 'long long',
            'uval_t': 'unsigned long long',
            'sval_t': 'long long',
            'ea32_t': 'unsigned int',
            'ea64_t': 'unsigned long long',
            'error_t': 'int',
            'op_dtype_t': 'unsigned char',
            'inode_t': 'unsigned long long',
            'diffpos_t': 'unsigned long',
            'qtime32_t': 'int',
            'qtime64_t': 'unsigned long long',
            'flags_t': 'unsigned int',
            'flags64_t': 'unsigned long long',
            'tid_t': 'unsigned long long',
            'bgcolor_t': 'unsigned int',
            'qhandle_t': 'int',
            'comp_t': 'unsigned char',
            'cm_t': 'unsigned char',
            'atype_t': 'int',
            'idastate_t': 'int',
            'nodeidx64_t': 'unsigned long long',
            'nodeidx32_t': 'unsigned int',
            'nodeidx_t': 'unsigned long long',
            'reftype_t': 'unsigned char',
            'type_t': 'unsigned char',
            'p_list': 'unsigned char',
            'color_t': 'unsigned char',
            'enum_t': 'unsigned long long',
            'bmask_t': 'unsigned long long',
            'const_t': 'unsigned long long',
            'tif_cursor_t': 'unsigned long long',
            'cpidx_t': 'int',
            'cplen_t': 'int',
            'twidget_type_t': 'int',
            'input_event_modifiers_t': 'int',
            'view_event_state_t': 'int',
            'optype_t': 'unsigned char',
            'help_t': 'int',
            'pid_t': 'int',
            'thid_t': 'int',
            'register_class_t': 'unsigned char',
            'bpttype_t': 'int',
            'mangled_name_type_t': 'int',
            'diff_degree_t': 'ssize_t',
            'diridx_t': 'unsigned long long',
            'blob_idx_t': 'unsigned long long',
            'fixup_type_t': 'unsigned short',
            'graph_id_t': 'unsigned long long',
            'layout_type_t': 'int',
            'ignore_name_def_t': 'int',
            'p_string': 'unsigned char',
            'bmask64_t': 'unsigned long long',
            'bte_t': 'unsigned char',
            'type_sign_t': 'int',
            'argloc_type_t': 'int',
            'biggest_t': 'unsigned long',
            'regnum_t': 'short',
            'lxtype': 'unsigned short',
            'utc_timestamp_t': 'unsigned long long',
            'lofi_timestamp_t': 'unsigned long long',
            'problist_id_t': 'unsigned char',
            'nfds_t': 'unsigned long',
            'regoff_t': 'unsigned long long',
            'srclang_t': 'int'
        }
        if tname in rtypes.keys():
            resolved = rtypes[tname]
            t2sz = {
                    'char': 1,
                    'short': 2,
                    'int': 4,
                    'long': 8,
                    'long long': 8,
                    'unsigned char': 1,
                    'unsigned short': 2,
                    'unsigned int': 4,
                    'unsigned long': 8,
                    'unsigned long long': 8,
                    'ssize_t': 8,
            }
            size = t2sz[resolved]
        else:
            resolved = tname
            size = None
        return resolved, size

    def __render_rets(self, rets):
        import ida_lines as il
        h = lambda s, c: f"{il.SCOLOR_ON}{c}{s}{il.SCOLOR_OFF}{c}"
        ha = lambda strs, cs: "".join([ h(s, c) for s, c in zip(strs, cs) ])
        tmp = []
        for i in range(len(rets)):
            if rets[i] == "void":
                continue
            tmp.append(ha( [ rets[i] ], [ il.SCOLOR_REG ]))

        retstr = ha([", "], [il.SCOLOR_DEFAULT]).join(tmp)
        return retstr

    def __render_args(self, args, types, defaults):
        import ida_lines as il
        h = lambda s, c: f"{il.SCOLOR_ON}{c}{s}{il.SCOLOR_OFF}{c}"
        ha = lambda strs, cs: "".join([ h(s, c) for s, c in zip(strs, cs) ])
        tmp = []
        for i in range(len(args)):
            if types[i] is None and defaults[i] is None:
                tmp.append(ha( [ f"{args[i]}" ], [ il.SCOLOR_LOCNAME ]))
            elif types[i] is None and defaults[i] is not None:
                tmp.append(ha([ f"{args[i]}", " = ", f"{defaults[i]}" ],
                    [ il.SCOLOR_LOCNAME, il.SCOLOR_DEFAULT, il.SCOLOR_NUMBER ]))
            elif types[i] is not None and defaults[i] is None:
               tmp.append(ha([ f"{args[i]}", ": ", f"{types[i]}", ],
                   [ il.SCOLOR_LOCNAME, il.SCOLOR_DEFAULT, il.SCOLOR_REG, ]))
            elif types[i] is not None and defaults[i] is not None:
               tmp.append(ha([ f"{args[i]}", ": ", f"{types[i]}", " = ", f"{defaults[i]}" ],
                   [ il.SCOLOR_LOCNAME, il.SCOLOR_DEFAULT, il.SCOLOR_REG,
                     il.SCOLOR_DEFAULT, il.SCOLOR_NUMBER ]))

        argstr = ha([", "], [il.SCOLOR_DEFAULT]).join(tmp)
        return argstr


    def __render_proto(self, name, args, types, defaults, rets, is_ctor = False):
        import ida_lines as il
        h = lambda s, c: f"{il.SCOLOR_ON}{c}{s}{il.SCOLOR_OFF}{c}"
        ha = lambda strs, cs: "".join([ h(s, c) for s, c in zip(strs, cs) ])
        argstr = self.__render_args(args, types, defaults)
        if is_ctor and len(rets) == 0:
            rets = [ name ]
        retstr = self.__render_rets(rets)

        proto = ha([ f"{name}", "(" ],
                   [ il.SCOLOR_MACRO if is_ctor else il.SCOLOR_CNAME, il.SCOLOR_DEFAULT ]) + \
                   f"{argstr}"

        if len(retstr) > 0:
            proto += ha( [ ") -> ", ], [ il.SCOLOR_DEFAULT, ]) + retstr
        else:
            proto += ha( [")" ], [ il.SCOLOR_DEFAULT ])

        return proto

    def __render_constant(self, name, attr):
        import ida_lines as il
        h = lambda s, c: f"{il.SCOLOR_ON}{c}{s}{il.SCOLOR_OFF}{c}"
        ha = lambda strs, cs: "".join([ h(s, c) for s, c in zip(strs, cs) ])
        out = ha([ f"{name.ljust(48)}", f" = ",            f"{attr:#018x}", ],
                 [ il.SCOLOR_DNAME,     il.SCOLOR_DEFAULT, il.SCOLOR_NUMBER ])
        return out

    def __render_default(self, name):
        import ida_lines as il
        h = lambda s, c: f"{il.SCOLOR_ON}{c}{s}{il.SCOLOR_OFF}{c}"
        ha = lambda strs, cs: "".join([ h(s, c) for s, c in zip(strs, cs) ])
        out = ha([ f"{name.ljust(48)}", ], [ il.SCOLOR_UNKNAME, ])
        return out

    def __render_int_member(self, name, typ, val):
        import ida_lines as il
        h = lambda s, c: f"{il.SCOLOR_ON}{c}{s}{il.SCOLOR_OFF}{c}"
        ha = lambda strs, cs: "".join([ h(s, c) for s, c in zip(strs, cs) ])
        _, sz = self.__resolve_type(typ)
        if sz is None:
            val_fmt = f"{val:#018x}"
        else:
            val_fmt = {
                1: f"{val:#04x}",
                2: f"{val:#06x}",
                4: f"{val:#010x}",
                8: f"{val:#018x}",
            }[sz]
        pref_len = len(f"{name}: {typ}")
        eq_pad = f" {'='.rjust(48-pref_len)} "
        out = ha([ f"{name}", ": ", f"{typ}", eq_pad, val_fmt ],
                 [ il.SCOLOR_LOCNAME, il.SCOLOR_DEFAULT, il.SCOLOR_REG, il.SCOLOR_DEFAULT,
                   il.SCOLOR_NUMBER ])
        return out

    def __render_docstr(self, doc, name):
        import ida_lines as il
        h = lambda s, c: f"{il.SCOLOR_ON}{c}{s}{il.SCOLOR_OFF}{c}"
        ha = lambda strs, cs: "".join([ h(s, c) for s, c in zip(strs, cs) ])

        if doc is None:
            return ""

        # proto = (args, types, defaults, rets)
        out = []
        ign = False
        for l in doc.splitlines():
            l = l.strip(" \n\r\t")
            m = re.match(f"(\\d). {name}\\(", l)
            if len(l) == 0:
                continue
            elif m is not None or "This function has the following signatures:" in l:
                # prototype definition
                continue
            else:
                # re-wrap docstring to 128 chars
                final = []
                curline = ""
                tmp = l.split(" ")
                for i in range(len(tmp)):
                    if len(curline) + len(tmp[i]) + 1 > 128:
                         final.append(f"{curline}")
                         curline = f"{tmp[i]} "
                    else:
                         curline += f"{tmp[i]} "
                if len(curline) > 0:
                    final.append(f"{curline}")

                out.append("\n".join(final))
        return "\n".join(out)

    def __parse_arg(self, arg):
        arg = arg.strip(" ")
        default = None
        typ = None
        if "=" in arg:
            arg, default = [ z.strip(" ") for z in arg.split("=") ]
        if ":" in arg:
            arg, typ = [ z.strip(" ") for z in arg.split(":") ]
        # Swig auto-renames certain argument names if they are also
        # python keywords (for example from -> _from)
        arg = arg.lstrip("_")
        return arg, typ, default

    def __proto_from_docstring(self, name, doc, altname = None):
        import re
        out = []
        args, types, defaults, rets = [], [], [], []
        if doc is None or len(doc) == 0:
            out.append((args, types, defaults, rets))
            return out
        if altname is not None:
            name = altname
        for l in doc.splitlines():
            m = re.match(f"    (\\d). {name}\\(", l)
            if m:
                if len(args + types + defaults + rets) > 0:
                    out.append((args, types, defaults, rets))
                args, types, defaults, rets = [], [], [], []

                l = l[len("    0. "):]

                # return types
                if " -> " in l:
                    tmp = l.split(" -> ")[1].strip("() ")
                    if tmp == "void":
                        rets = []
                    else:
                        rets = [ t.strip(" ") for t in tmp.split(",") ]
                else:
                    rets = []

                # arguments, types, default values in prototype
                o = 0
                lvl = 1
                # poor man's context free grammar state machine finding
                # outermost group of parentheses
                for o in range(l.find("("), len(l)):
                    if l[o] == "(":
                        lvl += 1
                    elif l[o] == ")":
                        lvl -= 1
                        if lvl == 1:
                            tmp = l[l.find("(") + 1:o]
                            break
                else:
                    # couldn't find outermost parenthesis group, skip
                    continue

                if "void" in tmp:
                    args = []
                for t in tmp.split(","):
                    arg, typ, default = self.__parse_arg(t)
                    args.append(arg)
                    types.append(typ)
                    defaults.append(default)

        if len(args + types + defaults + rets) > 0:
            out.append((args, types, defaults, rets))
        if len(out) == 0:
            return [([], [], [], [])]
        return out

    def __proto_from_argspec(self, name, args, defaults, annotations):
        types = []
        _defaults = []
        rets = []
        out = []
        def __repr_type(typ):
            if type(typ) is str:
                # string annotation, leave as is
                return typ
            elif typ.__class__.__module__ in [ "typing", "types" ]:
                # type hint, leave as is
                return typ
            elif typ in [ bool, str, int, float ]:
                # builtin type, format as string
                return typ.__name__
            else:
                # anything complex, leave as is
                return typ.__class__.__name__

        for i, arg in enumerate(args):
            if arg not in annotations.keys():
                types.append(None)
            else:
                types.append(__repr_type(annotations[arg]))

            if defaults and i >= len(args) - len(defaults):
                z = i - (len(args) - len(defaults))
                _defaults.append(defaults[z])
            else:
                _defaults.append(None)
        if "return" not in annotations.keys():
            rets = []
        elif annotations["return"] == "void":
            rets = []
        elif type(annotations["return"]) == list:
            rets = [ __repr_type(r) for r in annotations["return"] ]
        else:
            rets = [ __repr_type(annotations["return"]) ]

        out.append((args, types, _defaults, rets))
        return out

    def build_hints(self, names, ns):
        out = []
        W_CMEMB = 258
        W_CTOR  = 257
        W_FUNC  = 256
        var_docs = {}
        try:
            var_docs = IDAPython_GetDocstrings(ns)
        except:
            pass

        for name in names:
            try:
                attr = getattr(ns, name)
                is_prop = False
                pclass = None
                try:
                    is_prop = type(getattr(type(ns), name)) is property
                except:
                    pass
                is_int = type(attr) == int
                is_spo = "SwigPyObject" in str(type(attr))
                is_typing = type(attr).__module__ == "typing"
                if is_typing:
                    # Ignore typing-related imports ("from typing import X" ...)
                    continue
                if is_prop:
                    pclass = getattr(ns, "__class__")
                    mod, cls = pclass.__module__, pclass.__name__
                    var_docs = IDAPython_GetDocstrings(pclass)
                    doc = var_docs[name] if name in var_docs.keys() else ""
                    docr  = self.__render_docstr(doc, name)

                    if is_int or is_spo:
                        # class member, integral type or SwigPyObject
                        try:
                            # get low-level swig auto generated function
                            getter = getattr(getattr(sys.modules[mod], f"_{mod}"), f"{cls}_{name}_get")
                            typ = inspect.getdoc(getter).split(" -> ")[1]
                        except:
                            typ = "unk"
                        if is_int:
                            hint = self.__render_int_member(name, typ, attr)
                        else:
                            hint = self.__render_args([ name ], [ typ ], [ None ])
                        out.append((name, hint, docr, [ W_CMEMB ]))
                    else:
                        # class member, complex type, property, no SwigPyObject
                        annots = getattr(pclass, "__annotations__")
                        if name in annots.keys():
                            # if we have a type annnotation, pick that
                            typ = annots[name]
                        else:
                            # if we don't have a type annotation, take the python type
                            typ = type(attr).__name__
                        hint = self.__render_args([ name ], [ typ ], [ None ])
                        out.append((name, hint, docr, [ W_CMEMB ]))
                elif is_int:
                    # constant
                    hint = self.__render_constant(name, attr)
                    if name in var_docs.keys():
                        doc = var_docs[name]
                    else:
                        doc = ""
                    docr  = self.__render_docstr(doc, name)
                    out.append((name, hint, docr, [ W_CMEMB ]))
                elif inspect.isfunction(attr) or inspect.ismethod(attr) or inspect.isclass(attr):
                    # function or constructor
                    args, varargs, _, defaults, _, _, annots = inspect.getfullargspec(attr)
                    doc = inspect.getdoc(attr)
                    docr = self.__render_docstr(doc, name)
                    altname = None
                    is_ctor = inspect.isclass(attr)
                    weight = W_CTOR if is_ctor else W_FUNC
                    if name not in str(attr):
                        # Some functions are mapped to each other. The docstring
                        # parser can only extract prototypes from overloaded
                        # functions if it knows the name of the target function
                        altname = str(attr).split(" ")[1]
                    if varargs == "args" and doc is not None:
                        # Overloaded function, retrieve prototype from comment and
                        # insert one entry per prototype
                        prots = self.__proto_from_docstring(name, doc, altname = altname)
                        for prot in prots:
                            hint = self.__render_proto(name, *prot, is_ctor = is_ctor)
                            out.append((name, hint, docr, [ weight ]))
                    else:
                        # Regular function, retrieve prototype from argspec
                        prot = self.__proto_from_argspec(name, args, defaults, annots)[0]
                        hint = self.__render_proto(name, *prot, is_ctor = is_ctor)
                        out.append((name, hint, docr, [ weight ]))
                elif inspect.isclass(type(attr)) and type(attr).__name__ == "str":
                    # class member, string
                    if name in var_docs.keys():
                        doc = var_docs[name]
                    else:
                        doc = ""
                    docr  = self.__render_docstr(doc, name)
                    hint = self.__render_default(name)
                    out.append((name, hint, docr, [] ))
                elif inspect.isclass(type(attr)) and not callable(attr):
                    # class member, complex type
                    typ = type(attr).__name__
                    if typ == "module" and ns.__name__ != "__main__":
                        # hide submodules that show up just because they were
                        # imported by code in the module we're inspecting
                        continue
                    doc = inspect.getdoc(attr)
                    if doc is None:
                        doc = ""
                    docr  = self.__render_docstr(doc, name)
                    hint = self.__render_args([ name ], [ typ ], [ None ])
                    out.append((name, hint, docr, [ W_CMEMB ]))
                else:
                    doc = inspect.getdoc(attr)
                    if doc is None:
                        doc = ""
                    docr  = self.__render_docstr(doc, name)
                    hint = self.__render_default(name)
                    out.append((name, hint, docr, [] ))
            except:
                out.append((name, name, "", [] ))
                # self.debug("build_hint(%s) got an exception:\n%s", name, traceback.format_exc())
                pass

        out = sorted(out, key = lambda r: sum([ 1 << x for x in r[3] ]))
        comps, hints, docs, _ = zip(*out)
        return list(comps), list(hints), list(docs)

    def debug(self, *args):
        try:
            msg = args[0] % args[1:]
            print("IDAPython_Completion_Util: %s" % msg)
        except Exception as e:
            print("debug() got exception during debug(*args=%s):\n%s" % (
                str(args),
                traceback.format_exc()))

    def dir_namespace(self, m, prefix):
        return [x for x in dir(m) if x.startswith(prefix)]

    def maybe_extend_syntactically(self, ns, name, line, syntax_char):
        to_add = None
        try:
            attr = getattr(ns, name)
            # Is it callable?
            if callable(attr):
                if not line.startswith("?"):
                    to_add = "("
            # Is it iterable?
            elif isinstance(attr, string_types) or getattr(attr, '__iter__', False):
                to_add = "["
        except:
            # self.debug("maybe_extend_syntactically() got an exception:\n%s", traceback.format_exc())
            pass
        if to_add is not None and (syntax_char is None or to_add == syntax_char):
            name += to_add
        return name

    def get_candidates(self, qname, line, match_syntax_char):
        # self.debug("get_candidates(qname=%s, line=%s, match_syntax_char=%s)", qname, line, match_syntax_char)
        results = []
        MAGIC_METHODS = [ f"__{m}__" for m in [
            # as per https://docs.python.org/3/reference/datamodel.html (v3.12.3)
            "abs", "add", "aenter", "aexit", "aiter", "and", "anext",
            "annotations", "await", "bases", "bool", "buffer", "bytes", "call",
            "ceil", "class", "class_getitem", "closure", "code", "complex",
            "contains", "copy", "deepcopy", "defaults", "del", "delattr",
            "delete", "delitem", "dict", "dir", "divmod", "doc", "enter", "eq",
            "exit", "file", "float", "floor", "floordiv", "format", "fspath",
            "func", "future", "ge", "get", "getattr", "getattribute", "getitem",
            "getnewargs", "getstate", "globals", "gt", "hash", "iadd", "iand",
            "ifloordiv", "ilshift", "imatmul", "imod", "imul", "index", "init",
            "init_subclass", "instancecheck", "int", "invert", "ior", "ipow",
            "irshift", "isub", "iter", "itruediv", "ixor", "kwdefaults", "le",
            "len", "length_hint", "lshift", "lt", "match_args", "matmul",
            "missing", "mod", "module", "mro_entries", "mul", "name", "ne",
            "neg", "new", "next", "objclass", "or", "pos", "pow", "prepare",
            "qualname", "radd", "rand", "rdivmod", "reduce", "reduce_ex",
            "release_buffer", "repr", "reversed", "rfloordiv", "rlshift",
            "rmatmul", "rmod", "rmul", "ror", "round", "rpow", "rrshift",
            "rshift", "rsub", "rtruediv", "rxor", "self", "set", "set_name",
            "setattr", "setitem", "sizeof", "slots", "str", "sub",
            "subclasscheck", "subclasses", "traceback", "truediv", "trunc",
            "type_params", "typing_prepare_subst", "typing_subst", "weakref",
            "xor", "builtins",
            # and some more (manually picked)
            "cached", "loader", "package", "spec", "subclasshook",
        ]]

        # and some Swig internals that are decorated differently
        MAGIC_METHODS.extend([
            "__swig_destroy__",
            "_SwigNonDynamicMeta",
            "_swig_python_version_info",
            "_swig_add_metaclass",
            "_swig_repr",
            "_swig_setattr_nondynamic_class_variable",
            "_swig_setattr_nondynamic_instance_variable",
            "thisown", "this", "weakref",
            "cvar", "_real_cvar", "_wrap_cvar",
            "SWIG_PYTHON_LEGACY_BOOL",
        ])

        try:
            ns = sys.modules['__main__']
            parts = qname.split('.')
            # self.debug("get_candidates() got parts: %s", parts)
            for i in range(0, len(parts) - 1):
                ns = getattr(ns, parts[i])
        except Exception as e:
            # self.debug("get_candidates() got exception:\n%s", traceback.format_exc())
            pass
        else:
            # search in the namespace
            last_token = parts[-1]
            results = self.dir_namespace(ns, last_token)
            # self.debug("get_candidates() completions for %s in %s: %s", last_token, ns, results)

            # no completion found? looking from the global scope? then try the builtins
            if not results and len(parts) == 1:
                results = self.dir_namespace(builtins, last_token)
                # self.debug("get_candidates() completions for %s in %s: %s", last_token, builtins, results)
            if last_token not in [ "_", "__" ]:
                # only filter out __magic_methods__ if user doesn't explicitly
                # look for something with a "_" or "__" prefix.
                results = [ r for r in results if
                    not (r in MAGIC_METHODS) and # magic methods
                    not (r.startswith(f"_ida_") and r in sys.modules) and # low-level module
                    not (r.startswith(f"__get")) and # property getters
                    not (r.startswith(f"__set")) and # property setters
                    not (r.endswith(f"__from_ptrval__")) # swig
                ]

            results, hints, docs = self.build_hints(results, ns)

            docs = [ "    " + d.replace("\n", "\n    ") if len(d) > 0 else "" for d in docs ]

            results = map(lambda r: self.maybe_extend_syntactically(ns, r, line, match_syntax_char), results)

            ns_parts = parts[:-1]
            results = list(map(lambda r: ".".join(ns_parts + [r]), results))
            # self.debug("get_candidates() => '%s', '%s'", str(results), str(hints))
            return results, hints, docs

    QNAME_PAT = re.compile(r"([a-zA-Z_]([a-zA-Z0-9_\.]*)?)")

    def __call__(self, line, x):
        try:
            # self.debug("__call__(line=%s, x=%s)", line, x)
            uline = line.decode("UTF-8") if sys.version_info.major < 3 else line
            result = None

            # Kludge: if the we are past the last char, and that char is syntax:
            #    idaapi.print(
            #                 ^
            # then we want to backtrack to the previous non-syntax char,
            # and then instruct get_candidates() to not extend the match
            # with possible syntax.
            match_syntax_char = None
            if x > 0 and uline[x-1] in "[({":
                match_syntax_char = uline[x-1]
                x -= 1

            # Find what looks like an identifier (possibly qualified)
            for match in re.finditer(self.QNAME_PAT, uline):
                qname, start, end = match.group(1), match.start(1), match.end(1)
                if sys.version_info.major < 3:
                    qname = qname.encode("UTF-8")
                if x >= start and x <= end:
                    matches, hints, docs = self.get_candidates(qname, line, match_syntax_char)
                    rep_x, end = start, end + (1 if match_syntax_char else 0)
                    result = matches, hints, docs, rep_x, end

            # self.debug("__call__() => '%s'", str(result))
            return result
        except Exception as e:
            # self.debug("__call__() got exception:\n%s", traceback.format_exc())
            pass

# Instantiate an IDAPython command completion object (for use with IDA's CLI bar)
IDAPython_Completion = __IDAPython_Completion_Util()

def _listify_types(*classes):
    for cls in classes:
        cls.at = cls.__getitem__ # '__getitem__' has bounds checkings
        cls.__len__ = cls.size
        cls.__iter__ = _bounded_getitem_iterator
        cls.append = cls.push_back

# The general callback format of notify_when() is:
#    def notify_when_callback(nw_code)
# In the case of NW_OPENIDB, the callback is:
#    def notify_when_callback(nw_code, is_old_database)
NW_OPENIDB    = 0x0001
"""Notify when the database is opened. Its callback is of the form: def notify_when_callback(nw_code, is_old_database)"""
NW_CLOSEIDB   = 0x0002
"""Notify when the database is closed. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_INITIDA    = 0x0004
"""Notify when the IDA starts. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_TERMIDA    = 0x0008
"""Notify when the IDA terminates. Its callback is of the form: def notify_when_callback(nw_code)"""
NW_REMOVE     = 0x0010
"""Use this flag with other flags to uninstall a notifywhen callback"""


_notify_when_dispatcher = None

def notify_when(when, callback):
    """
    Register a callback that will be called when an event happens.
    @param when: one of NW_XXXX constants
    @param callback: This callback prototype varies depending on the 'when' parameter:
                     The general callback format:
                         def notify_when_callback(nw_code)
                     In the case of NW_OPENIDB:
                         def notify_when_callback(nw_code, is_old_database)
    @return: Boolean
    """
    global _notify_when_dispatcher
    import ida_idp
    if _notify_when_dispatcher is None:
        _notify_when_dispatcher = ida_idp._notify_when_dispatcher_t()
    return _notify_when_dispatcher.notify_when(when, callback)


# Since version 5.5, PyQt5 doesn't simply print the PyQt exceptions by default
# anymore: https://github.com/baoboa/pyqt5/commit/1e1d8a3ba677ef3e47b916b8a5b9c281d0f8e4b5#diff-848704a82f6a6e3a13112145ce32ac69L63
# The default behavior now is that qFatal() is called, causing the application
# to abort().
# We do not want that to happen in IDA, and simply having a sys.excepthook
# that is different from sys.__excepthook__ is enough for PyQt5 to return
# to the previous behavior
def __install_excepthook():
    real_hook = sys.excepthook
    sys.excepthook = lambda *args: real_hook(*args)
__install_excepthook()


# ------------------------------------------------------------
class IDAPython_displayhook:
    def __init__(self):
        self.orig_displayhook = sys.displayhook

    def format_seq(self, num_printer, storage, item, opn, cls):
        storage.append(opn)
        for idx, el in enumerate(item):
            if idx > 0:
                storage.append(', ')
            self.format_item(num_printer, storage, el)
        storage.append(cls)

    def format_item(self, num_printer, storage, item):
        if item is None or isinstance(item, bool):
            storage.append(repr(item))
        elif isinstance(item, string_types):
            storage.append(format_basestring(item))
        elif isinstance(item, integer_types):
            storage.append(num_printer(item))
        elif isinstance(item, list):
            self.format_seq(num_printer, storage, item, '[', ']')
        elif isinstance(item, tuple):
            self.format_seq(num_printer, storage, item, '(', ')')
        elif isinstance(item, set):
            self.format_seq(num_printer, storage, item, 'set([', '])')
        elif isinstance(item, (dict,)):
            storage.append('{')
            for idx, pair in enumerate(item.items()):
                if idx > 0:
                    storage.append(', ')
                self.format_item(num_printer, storage, pair[0])
                storage.append(": ")
                self.format_item(num_printer, storage, pair[1])
            storage.append('}')
        else:
            storage.append(repr(item))

    def _print_hex(self, x):
        return hex(x)

    def displayhook_format(self, item):
        storage = []
        import ida_idp
        num_printer = self._print_hex
        dn = ida_idp.ph_get_flag() & ida_idp.PR_DEFNUM
        if dn == ida_idp.PRN_OCT:
            num_printer = oct
        elif dn == ida_idp.PRN_DEC:
            num_printer = str
        elif dn == ida_idp.PRN_BIN:
            num_printer = bin
        self.format_item(num_printer, storage, item)
        return "".join(storage)

    def displayhook(self, item):
        if item is None or type(item) is bool:
            self.orig_displayhook(item)
            return
        try:
            clob = self.displayhook_format(item)
            sys.stdout.write("%s\n" % clob)
        except:
            import traceback
            traceback.print_exc()
            self.orig_displayhook(item)

_IDAPython_displayhook = IDAPython_displayhook()
sys.displayhook = _IDAPython_displayhook.displayhook

def _make_one_time_warning_message(bad_attr, new_attr):
    warned = [False]
    def f():
        if not warned[0]:
            import traceback
            # skip two frames to get the actual line which triggered the  access
            f = sys._getframe().f_back.f_back
            traceback.print_stack(f)
            print("Please use \"%s\" instead of \"%s\" (\"%s\" is kept for backward-compatibility, and will be removed soon.)" % (new_attr, bad_attr, bad_attr))
            warned[0] = True
    return f

def _make_missed_695bwcompat_property(bad_attr, new_attr, has_setter):
    _notify_bwcompat = _make_one_time_warning_message(bad_attr, new_attr)
    def _getter(self):
        _notify_bwcompat()
        return getattr(self, new_attr)
    def _setter(self, v):
        _notify_bwcompat()
        return setattr(self, new_attr, v)
    return property(_getter, _setter if has_setter else None)



#</pycode(py_idaapi)>
