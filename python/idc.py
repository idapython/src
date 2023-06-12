#!/usr/bin/env python
#---------------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler
#
# Original IDC.IDC:
# Copyright (c) 1990-2010 Ilfak Guilfanov
#
# Python conversion:
# Copyright (c) 2004-2010 Gergely Erdelyi <gergely.erdelyi@d-dome.net>
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#---------------------------------------------------------------------
# idc.py - IDC compatibility module
#---------------------------------------------------------------------
"""
IDC compatibility module

This file contains IDA built-in function declarations and internal bit
definitions.  Each byte of the program has 32-bit flags (low 8 bits keep
the byte value). These 32 bits are used in get_full_flags/get_flags functions.

This file is subject to change without any notice.
Future versions of IDA may use other definitions.
"""
from __future__ import print_function
# FIXME: Perhaps those should be loaded on-demand
import ida_idaapi
import ida_auto
import ida_dbg
import ida_diskio
import ida_entry
import ida_enum
import ida_expr
import ida_fixup
import ida_frame
import ida_funcs
import ida_gdl
import ida_ida
import ida_idc
import ida_bytes
import ida_idd
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_moves
import ida_nalt
import ida_name
import ida_netnode
import ida_offset
import ida_pro
import ida_search
import ida_segment
import ida_segregs
import ida_struct
import ida_typeinf
import ida_ua
import ida_xref

import _ida_idaapi

import os
import re
import struct
import time
import types
import sys

__EA64__ = ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF
WORDMASK = 0xFFFFFFFFFFFFFFFF if __EA64__ else 0xFFFFFFFF # just there for bw-compat purposes; please don't use
class DeprecatedIDCError(Exception):
    """
    Exception for deprecated function calls
    """
    pass

__warned_deprecated_proto_confusion = {}
def __warn_once_deprecated_proto_confusion(what, alternative):
    if what not in __warned_deprecated_proto_confusion:
        print("NOTE: idc.%s is deprecated due to signature confusion with %s. Please use %s instead" % (
            what,
            alternative,
            alternative))
        __warned_deprecated_proto_confusion[what] = True

def _IDC_GetAttr(obj, attrmap, attroffs):
    """
    Internal function to generically get object attributes
    Do not use unless you know what you are doing
    """
    if attroffs in attrmap and hasattr(obj, attrmap[attroffs][1]):
        return getattr(obj, attrmap[attroffs][1])
    else:
        errormsg = "attribute with offset %d not found, check the offset and report the problem" % attroffs
        raise KeyError(errormsg)


def _IDC_SetAttr(obj, attrmap, attroffs, value):
    """
    Internal function to generically set object attributes
    Do not use unless you know what you are doing
    """
    # check for read-only atributes
    if attroffs in attrmap:
        if attrmap[attroffs][0]:
            raise KeyError("attribute with offset %d is read-only" % attroffs)
        elif hasattr(obj, attrmap[attroffs][1]):
            return setattr(obj, attrmap[attroffs][1], value)
    errormsg = "attribute with offset %d not found, check the offset and report the problem" % attroffs
    raise KeyError(errormsg)


BADADDR         = ida_idaapi.BADADDR # Not allowed address value
BADSEL          = ida_idaapi.BADSEL  # Not allowed selector value/number
SIZE_MAX        = _ida_idaapi.SIZE_MAX
ida_ida.__set_module_dynattrs(
    __name__,
    {
        "MAXADDR" : (lambda: ida_ida.inf_get_privrange_start_ea(), None),
    })

#
#      Flag bit definitions (for get_full_flags())
#
MS_VAL  = ida_bytes.MS_VAL             # Mask for byte value
FF_IVL  = ida_bytes.FF_IVL             # Byte has value ?

# Do flags contain byte value? (i.e. has the byte a value?)
# if not, the byte is uninitialized.

def has_value(F):     return ((F & FF_IVL) != 0)     # any defined value?

def byte_value(F):
    """
    Get byte value from flags
    Get value of byte provided that the byte is initialized.
    This macro works ok only for 8-bit byte machines.
    """
    return (F & MS_VAL)


def is_loaded(ea):
    """Is the byte initialized?"""
    return has_value(get_full_flags(ea))  # any defined value?

MS_CLS   = ida_bytes.MS_CLS   # Mask for typing
FF_CODE  = ida_bytes.FF_CODE  # Code ?
FF_DATA  = ida_bytes.FF_DATA  # Data ?
FF_TAIL  = ida_bytes.FF_TAIL  # Tail ?
FF_UNK   = ida_bytes.FF_UNK   # Unknown ?

def is_code(F):       return ((F & MS_CLS) == FF_CODE) # is code byte?
def is_data(F):       return ((F & MS_CLS) == FF_DATA) # is data byte?
def is_tail(F):       return ((F & MS_CLS) == FF_TAIL) # is tail byte?
def is_unknown(F):    return ((F & MS_CLS) == FF_UNK)  # is unexplored byte?
def is_head(F):       return ((F & FF_DATA) != 0)      # is start of code/data?

#
#      Common bits
#
MS_COMM  = ida_bytes.MS_COMM  # Mask of common bits
FF_COMM  = ida_bytes.FF_COMM  # Has comment?
FF_REF   = ida_bytes.FF_REF   # has references?
FF_LINE  = ida_bytes.FF_LINE  # Has next or prev cmt lines ?
FF_NAME  = ida_bytes.FF_NAME  # Has user-defined name ?
FF_LABL  = ida_bytes.FF_LABL  # Has dummy name?
FF_FLOW  = ida_bytes.FF_FLOW  # Exec flow from prev instruction?
FF_ANYNAME = FF_LABL | FF_NAME

def is_flow(F):       return ((F & FF_FLOW) != 0)
def isExtra(F):      return ((F & FF_LINE) != 0)
def isRef(F):        return ((F & FF_REF)  != 0)
def hasName(F):      return ((F & FF_NAME) != 0)
def hasUserName(F):  return ((F & FF_ANYNAME) == FF_NAME)

MS_0TYPE  = ida_bytes.MS_0TYPE  # Mask for 1st arg typing
FF_0VOID  = ida_bytes.FF_0VOID  # Void (unknown)?
FF_0NUMH  = ida_bytes.FF_0NUMH  # Hexadecimal number?
FF_0NUMD  = ida_bytes.FF_0NUMD  # Decimal number?
FF_0CHAR  = ida_bytes.FF_0CHAR  # Char ('x')?
FF_0SEG   = ida_bytes.FF_0SEG   # Segment?
FF_0OFF   = ida_bytes.FF_0OFF   # Offset?
FF_0NUMB  = ida_bytes.FF_0NUMB  # Binary number?
FF_0NUMO  = ida_bytes.FF_0NUMO  # Octal number?
FF_0ENUM  = ida_bytes.FF_0ENUM  # Enumeration?
FF_0FOP   = ida_bytes.FF_0FOP   # Forced operand?
FF_0STRO  = ida_bytes.FF_0STRO  # Struct offset?
FF_0STK   = ida_bytes.FF_0STK   # Stack variable?

MS_1TYPE  = ida_bytes.MS_1TYPE  # Mask for 2nd arg typing
FF_1VOID  = ida_bytes.FF_1VOID  # Void (unknown)?
FF_1NUMH  = ida_bytes.FF_1NUMH  # Hexadecimal number?
FF_1NUMD  = ida_bytes.FF_1NUMD  # Decimal number?
FF_1CHAR  = ida_bytes.FF_1CHAR  # Char ('x')?
FF_1SEG   = ida_bytes.FF_1SEG   # Segment?
FF_1OFF   = ida_bytes.FF_1OFF   # Offset?
FF_1NUMB  = ida_bytes.FF_1NUMB  # Binary number?
FF_1NUMO  = ida_bytes.FF_1NUMO  # Octal number?
FF_1ENUM  = ida_bytes.FF_1ENUM  # Enumeration?
FF_1FOP   = ida_bytes.FF_1FOP   # Forced operand?
FF_1STRO  = ida_bytes.FF_1STRO  # Struct offset?
FF_1STK   = ida_bytes.FF_1STK   # Stack variable?

# The following macros answer questions like
#   'is the 1st (or 2nd) operand of instruction or data of the given type'?
# Please note that data items use only the 1st operand type (is...0)

def is_defarg0(F):    return ((F & MS_0TYPE) != FF_0VOID)
def is_defarg1(F):    return ((F & MS_1TYPE) != FF_1VOID)
def isDec0(F):       return ((F & MS_0TYPE) == FF_0NUMD)
def isDec1(F):       return ((F & MS_1TYPE) == FF_1NUMD)
def isHex0(F):       return ((F & MS_0TYPE) == FF_0NUMH)
def isHex1(F):       return ((F & MS_1TYPE) == FF_1NUMH)
def isOct0(F):       return ((F & MS_0TYPE) == FF_0NUMO)
def isOct1(F):       return ((F & MS_1TYPE) == FF_1NUMO)
def isBin0(F):       return ((F & MS_0TYPE) == FF_0NUMB)
def isBin1(F):       return ((F & MS_1TYPE) == FF_1NUMB)
def is_off0(F):       return ((F & MS_0TYPE) == FF_0OFF)
def is_off1(F):       return ((F & MS_1TYPE) == FF_1OFF)
def is_char0(F):      return ((F & MS_0TYPE) == FF_0CHAR)
def is_char1(F):      return ((F & MS_1TYPE) == FF_1CHAR)
def is_seg0(F):       return ((F & MS_0TYPE) == FF_0SEG)
def is_seg1(F):       return ((F & MS_1TYPE) == FF_1SEG)
def is_enum0(F):      return ((F & MS_0TYPE) == FF_0ENUM)
def is_enum1(F):      return ((F & MS_1TYPE) == FF_1ENUM)
def is_manual0(F):       return ((F & MS_0TYPE) == FF_0FOP)
def is_manual1(F):       return ((F & MS_1TYPE) == FF_1FOP)
def is_stroff0(F):    return ((F & MS_0TYPE) == FF_0STRO)
def is_stroff1(F):    return ((F & MS_1TYPE) == FF_1STRO)
def is_stkvar0(F):    return ((F & MS_0TYPE) == FF_0STK)
def is_stkvar1(F):    return ((F & MS_1TYPE) == FF_1STK)

#
#      Bits for DATA bytes
#
DT_TYPE  = ida_bytes.DT_TYPE & 0xFFFFFFFF  # Mask for DATA typing

FF_BYTE      = ida_bytes.FF_BYTE & 0xFFFFFFFF      # byte
FF_WORD      = ida_bytes.FF_WORD & 0xFFFFFFFF      # word
FF_DWORD      = ida_bytes.FF_DWORD & 0xFFFFFFFF      # dword
FF_QWORD      = ida_bytes.FF_QWORD & 0xFFFFFFFF      # qword
FF_TBYTE      = ida_bytes.FF_TBYTE & 0xFFFFFFFF      # tbyte
FF_STRLIT      = ida_bytes.FF_STRLIT & 0xFFFFFFFF      # ASCII ?
FF_STRUCT      = ida_bytes.FF_STRUCT & 0xFFFFFFFF      # Struct ?
FF_OWORD      = ida_bytes.FF_OWORD & 0xFFFFFFFF      # octaword (16 bytes)
FF_FLOAT     = ida_bytes.FF_FLOAT & 0xFFFFFFFF     # float
FF_DOUBLE    = ida_bytes.FF_DOUBLE & 0xFFFFFFFF    # double
FF_PACKREAL  = ida_bytes.FF_PACKREAL & 0xFFFFFFFF  # packed decimal real
FF_ALIGN     = ida_bytes.FF_ALIGN & 0xFFFFFFFF     # alignment directive

def is_byte(F):     return (is_data(F) and (F & DT_TYPE) == FF_BYTE)
def is_word(F):     return (is_data(F) and (F & DT_TYPE) == FF_WORD)
def is_dword(F):     return (is_data(F) and (F & DT_TYPE) == FF_DWORD)
def is_qword(F):     return (is_data(F) and (F & DT_TYPE) == FF_QWORD)
def is_oword(F):     return (is_data(F) and (F & DT_TYPE) == FF_OWORD)
def is_tbyte(F):     return (is_data(F) and (F & DT_TYPE) == FF_TBYTE)
def is_float(F):    return (is_data(F) and (F & DT_TYPE) == FF_FLOAT)
def is_double(F):   return (is_data(F) and (F & DT_TYPE) == FF_DOUBLE)
def is_pack_real(F): return (is_data(F) and (F & DT_TYPE) == FF_PACKREAL)
def is_strlit(F):    return (is_data(F) and (F & DT_TYPE) == FF_STRLIT)
def is_struct(F):   return (is_data(F) and (F & DT_TYPE) == FF_STRUCT)
def is_align(F):    return (is_data(F) and (F & DT_TYPE) == FF_ALIGN)

#
#      Bits for CODE bytes
#
MS_CODE  = ida_bytes.MS_CODE & 0xFFFFFFFF
FF_FUNC  = ida_bytes.FF_FUNC & 0xFFFFFFFF  # function start?
FF_IMMD  = ida_bytes.FF_IMMD & 0xFFFFFFFF  # Has Immediate value ?
FF_JUMP  = ida_bytes.FF_JUMP & 0xFFFFFFFF  # Has jump table

#
#      Loader flags
#
if ida_idaapi.uses_swig_builtins:
    _scope = ida_loader.loader_t
else:
    _scope = ida_loader
NEF_SEGS   = _scope.NEF_SEGS   # Create segments
NEF_RSCS   = _scope.NEF_RSCS   # Load resources
NEF_NAME   = _scope.NEF_NAME   # Rename entries
NEF_MAN    = _scope.NEF_MAN    # Manual load
NEF_FILL   = _scope.NEF_FILL   # Fill segment gaps
NEF_IMPS   = _scope.NEF_IMPS   # Create imports section
NEF_FIRST  = _scope.NEF_FIRST  # This is the first file loaded
NEF_CODE   = _scope.NEF_CODE   # for load_binary_file:
NEF_RELOAD = _scope.NEF_RELOAD # reload the file at the same place:
NEF_FLAT   = _scope.NEF_FLAT   # Autocreated FLAT group (PE)

#         List of built-in functions
#         --------------------------
#
# The following conventions are used in this list:
#   'ea' is a linear address
#   'success' is 0 if a function failed, 1 otherwise
#   'void' means that function returns no meaningful value (always 0)
#
#  All function parameter conversions are made automatically.
#
# ----------------------------------------------------------------------------
#                       M I S C E L L A N E O U S
# ----------------------------------------------------------------------------
def value_is_string(var): raise NotImplementedError("this function is not needed in Python")
def value_is_long(var):   raise NotImplementedError("this function is not needed in Python")
def value_is_float(var):  raise NotImplementedError("this function is not needed in Python")
def value_is_func(var):   raise NotImplementedError("this function is not needed in Python")
def value_is_pvoid(var):  raise NotImplementedError("this function is not needed in Python")
def value_is_int64(var):  raise NotImplementedError("this function is not needed in Python")

def to_ea(seg, off):
    """
    Return value of expression: ((seg<<4) + off)
    """
    return (seg << 4) + off

def form(format, *args):
    raise DeprecatedIDCError("form() is deprecated. Use python string operations instead.")

def substr(s, x1, x2):
    raise DeprecatedIDCError("substr() is deprecated. Use python string operations instead.")

def strstr(s1, s2):
    raise DeprecatedIDCError("strstr() is deprecated. Use python string operations instead.")

def strlen(s):
    raise DeprecatedIDCError("strlen() is deprecated. Use python string operations instead.")

def xtol(s):
    raise DeprecatedIDCError("xtol() is deprecated. Use python long() instead.")

def atoa(ea):
    """
    Convert address value to a string
    Return address in the form 'seg000:1234'
    (the same as in line prefixes)

    @param ea: address to format
    """
    return ida_kernwin.ea2str(ea)

def ltoa(n, radix):
    raise DeprecatedIDCError("ltoa() is deprecated. Use python string operations instead.")

def atol(s):
    raise DeprecatedIDCError("atol() is deprecated. Use python long() instead.")


def rotate_left(value, count, nbits, offset):
    """
    Rotate a value to the left (or right)

    @param value: value to rotate
    @param count: number of times to rotate. negative counter means
                  rotate to the right
    @param nbits: number of bits to rotate
    @param offset: offset of the first bit to rotate

    @return: the value with the specified field rotated
             all other bits are not modified
    """
    assert offset >= 0, "offset must be >= 0"
    assert nbits > 0, "nbits must be > 0"
    count %= nbits # no need to spin the wheel more than 1 rotation

    mask = 2**(offset+nbits) - 2**offset
    tmp = value & mask

    if count > 0:
        for x in range(count):
            if (tmp >> (offset+nbits-1)) & 1:
                tmp = (tmp << 1) | (1 << offset)
            else:
                tmp = (tmp << 1)
    else:
        for x in range(-count):
            if (tmp >> offset) & 1:
                tmp = (tmp >> 1) | (1 << (offset+nbits-1))
            else:
                tmp = (tmp >> 1)

    value = (value-(value&mask)) | (tmp & mask)

    return value


def rotate_dword(x, count): return rotate_left(x, count, 32, 0)
def rotate_word(x, count):  return rotate_left(x, count, 16, 0)
def rotate_byte(x, count):  return rotate_left(x, count, 8, 0)


# add_idc_hotkey return codes
IDCHK_OK        =  0   # ok
IDCHK_ARG       = -1   # bad argument(s)
IDCHK_KEY       = -2   # bad hotkey name
IDCHK_MAX       = -3   # too many IDC hotkeys

add_idc_hotkey = ida_kernwin.add_idc_hotkey
del_idc_hotkey = ida_kernwin.del_idc_hotkey
jumpto = ida_kernwin.jumpto
auto_wait = ida_auto.auto_wait


def eval_idc(expr):
    """
    Evaluate an IDC expression

    @param expr: an expression

    @return: the expression value. If there are problems, the returned value will be "IDC_FAILURE: xxx"
             where xxx is the error description

    @note: Python implementation evaluates IDC only, while IDC can call other registered languages
    """
    rv = ida_expr.idc_value_t()

    err = ida_expr.eval_idc_expr(rv, BADADDR, expr)
    if err:
        return "IDC_FAILURE: "+err
    else:
        if rv.vtype == '\x02': # long
            return rv.num
        elif rv.vtype == '\x07': # VT_STR
            return rv.c_str()
        else:
            raise NotImplementedError("eval_idc() supports only expressions returning strings or longs")


def EVAL_FAILURE(code):
    """
    Check the result of eval_idc() for evaluation failures

    @param code: result of eval_idc()

    @return: True if there was an evaluation error
    """
    return type(code) == bytes and code.startswith("IDC_FAILURE: ")


def save_database(idbname, flags=0):
    """
    Save current database to the specified idb file

    @param idbname: name of the idb file. if empty, the current idb
                    file will be used.
    @param flags: combination of ida_loader.DBFL_... bits or 0
    """
    if len(idbname) == 0:
        idbname = get_idb_path()
    mask = ida_loader.DBFL_KILL | ida_loader.DBFL_COMP | ida_loader.DBFL_BAK
    return ida_loader.save_database(idbname, flags & mask)

DBFL_BAK = ida_loader.DBFL_BAK # for compatiblity with older versions, eventually delete this

def validate_idb_names(do_repair = 0):
    """
    check consistency of IDB name records
    @param do_repair: try to repair netnode header it TRUE
    @return: number of inconsistent name records
    """
    return ida_nalt.validate_idb_names(do_repair)

qexit = ida_pro.qexit


def call_system(command):
    """
    Execute an OS command.

    @param command: command line to execute

    @return: error code from OS

    @note:
    IDA will wait for the started program to finish.
    In order to start the command in parallel, use OS methods.
    For example, you may start another program in parallel using
    "start" command.
    """
    return os.system(command)


def qsleep(milliseconds):
    """
    qsleep the specified number of milliseconds
    This function suspends IDA for the specified amount of time

    @param milliseconds: time to sleep
    """
    time.sleep(float(milliseconds)/1000)


load_and_run_plugin = ida_loader.load_and_run_plugin
plan_to_apply_idasgn = ida_funcs.plan_to_apply_idasgn


#----------------------------------------------------------------------------
#      C H A N G E   P R O G R A M   R E P R E S E N T A T I O N
#----------------------------------------------------------------------------


def delete_all_segments():
    """
    Delete all segments, instructions, comments, i.e. everything
    except values of bytes.
    """
    ea = ida_ida.cvar.inf.min_ea

    # Brute-force nuke all info from all the heads
    while ea != BADADDR and ea <= ida_ida.cvar.inf.max_ea:
        ida_name.del_local_name(ea)
        ida_name.del_global_name(ea)
        func = ida_funcs.get_func(ea)
        if func:
            ida_funcs.set_func_cmt(func, "", False)
            ida_funcs.set_func_cmt(func, "", True)
            ida_funcs.del_func(ea)
        ida_bytes.del_hidden_range(ea)
        seg = ida_segment.getseg(ea)
        if seg:
            ida_segment.set_segment_cmt(seg, "", False)
            ida_segment.set_segment_cmt(seg, "", True)
            ida_segment.del_segm(ea, ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT)

        ea = ida_bytes.next_head(ea, ida_ida.cvar.inf.max_ea)


create_insn = ida_ua.create_insn


def plan_and_wait(sEA, eEA, final_pass=True):
    """
    Perform full analysis of the range

    @param sEA: starting linear address
    @param eEA: ending linear address (excluded)
    @param final_pass: make the final pass over the specified range

    @return: 1-ok, 0-Ctrl-Break was pressed.
    """
    return ida_auto.plan_and_wait(sEA, eEA, final_pass)


def set_name(ea, name, flags=ida_name.SN_CHECK):
    """
    Rename an address

    @param ea: linear address
    @param name: new name of address. If name == "", then delete old name
    @param flags: combination of SN_... constants

    @return: 1-ok, 0-failure
    """
    return ida_name.set_name(ea, name, flags)

SN_CHECK      = ida_name.SN_CHECK    # Fail if the name contains invalid characters.
SN_NOCHECK    = ida_name.SN_NOCHECK  # Don't fail if the name contains invalid characters.
                                     # If this bit is set, all invalid chars
                                     # (not in NameChars or MangleChars) will be replaced
                                     # by '_'.
                                     # List of valid characters is defined in ida.cfg
SN_PUBLIC     = ida_name.SN_PUBLIC   # if set, make name public
SN_NON_PUBLIC = ida_name.SN_NON_PUBLIC # if set, make name non-public
SN_WEAK       = ida_name.SN_WEAK     # if set, make name weak
SN_NON_WEAK   = ida_name.SN_NON_WEAK # if set, make name non-weak
SN_AUTO       = ida_name.SN_AUTO     # if set, make name autogenerated
SN_NON_AUTO   = ida_name.SN_NON_AUTO # if set, make name non-autogenerated
SN_NOLIST     = ida_name.SN_NOLIST   # if set, exclude name from the list
                                     # if not set, then include the name into
                                     # the list (however, if other bits are set,
                                     # the name might be immediately excluded
                                     # from the list)
SN_NOWARN     = ida_name.SN_NOWARN   # don't display a warning if failed
SN_LOCAL      = ida_name.SN_LOCAL    # create local name. a function should exist.
                                     # local names can't be public or weak.
                                     # also they are not included into the list
                                     # of names they can't have dummy prefixes

set_cmt = ida_bytes.set_cmt


def make_array(ea, nitems):
    """
    Create an array.

    @param ea: linear address
    @param nitems: size of array in items

    @note: This function will create an array of the items with the same type as
    the type of the item at 'ea'. If the byte at 'ea' is undefined, then
    this function will create an array of bytes.
    """
    flags = ida_bytes.get_flags(ea)

    if ida_bytes.is_code(flags) or ida_bytes.is_tail(flags) or ida_bytes.is_align(flags):
        return False

    if ida_bytes.is_unknown(flags):
        flags = ida_bytes.FF_BYTE

    if ida_bytes.is_struct(flags):
        ti = ida_nalt.opinfo_t()
        assert ida_bytes.get_opinfo(ti, ea, 0, flags), "get_opinfo() failed"
        itemsize = ida_bytes.get_data_elsize(ea, flags, ti)
        tid = ti.tid
    else:
        itemsize = ida_bytes.get_item_size(ea)
        tid = BADADDR

    return ida_bytes.create_data(ea, flags, itemsize*nitems, tid)


def create_strlit(ea, endea):
    """
    Create a string.

    This function creates a string (the string type is determined by the
    value of get_inf_attr(INF_STRTYPE))

    @param ea: linear address
    @param endea: ending address of the string (excluded)
        if endea == BADADDR, then length of string will be calculated
        by the kernel

    @return: 1-ok, 0-failure

    @note: The type of an existing string is returned by get_str_type()
    """
    return ida_bytes.create_strlit(ea, 0 if endea == BADADDR else endea - ea, get_inf_attr(INF_STRTYPE))


create_data = ida_bytes.create_data


def create_byte(ea):
    """
    Convert the current item to a byte

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_byte(ea, 1)


def create_word(ea):
    """
    Convert the current item to a word (2 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_word(ea, 2)


def create_dword(ea):
    """
    Convert the current item to a double word (4 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_dword(ea, 4)


def create_qword(ea):
    """
    Convert the current item to a quadro word (8 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_qword(ea, 8)


def create_oword(ea):
    """
    Convert the current item to an octa word (16 bytes/128 bits)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_oword(ea, 16)


def create_yword(ea):
    """
    Convert the current item to a ymm word (32 bytes/256 bits)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_yword(ea, 32)


def create_float(ea):
    """
    Convert the current item to a floating point (4 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_float(ea, 4)


def create_double(ea):
    """
    Convert the current item to a double floating point (8 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_double(ea, 8)


def create_pack_real(ea):
    """
    Convert the current item to a packed real (10 or 12 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_packed_real(ea, ida_idp.ph_get_tbyte_size())


def create_tbyte(ea):
    """
    Convert the current item to a tbyte (10 or 12 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_tbyte(ea, ida_idp.ph_get_tbyte_size())


def create_struct(ea, size, strname):
    """
    Convert the current item to a structure instance

    @param ea: linear address
    @param size: structure size in bytes. -1 means that the size
        will be calculated automatically
    @param strname: name of a structure type

    @return: 1-ok, 0-failure
    """
    strid = ida_struct.get_struc_id(strname)

    if size == -1:
        size = ida_struct.get_struc_size(strid)

    return ida_bytes.create_struct(ea, size, strid)


create_custom_data = ida_bytes.create_custdata
create_align = ida_bytes.create_align


def define_local_var(start, end, location, name):
    """
    Create a local variable

    @param start: start of address range for the local variable
    @param end: end of address range for the local variable
    @param location: the variable location in the "[bp+xx]" form where xx is
                     a number. The location can also be specified as a
                     register name.
    @param name: name of the local variable

    @return: 1-ok, 0-failure

    @note: For the stack variables the end address is ignored.
           If there is no function at 'start' then this function.
           will fail.
    """
    func = ida_funcs.get_func(start)

    if not func:
        return 0

    # Find out if location is in the [bp+xx] form
    r = re.compile("\[([a-z]+)([-+][0-9a-fx]+)", re.IGNORECASE)
    m = r.match(location)

    if m:
        # Location in the form of [bp+xx]
        register = ida_idp.str2reg(m.group(1))
        if register == -1:
            return 0

        offset = int(m.group(2), 0)
        return 1 if ida_frame.define_stkvar(func, name, offset, ida_bytes.byte_flag(), None, 1) else 0
    else:
        # Location as simple register name
        return ida_frame.add_regvar(func, start, end, location, name, None)


del_items = ida_bytes.del_items

DELIT_SIMPLE   = ida_bytes.DELIT_SIMPLE   # simply undefine the specified item
DELIT_EXPAND   = ida_bytes.DELIT_EXPAND   # propogate undefined items, for example
                                          # if removing an instruction removes all
                                          # references to the next instruction, then
                                          # plan to convert to unexplored the next
                                          # instruction too.
DELIT_DELNAMES = ida_bytes.DELIT_DELNAMES # delete any names at the specified address(es)


def set_array_params(ea, flags, litems, align):
    """
    Set array representation format

    @param ea: linear address
    @param flags: combination of AP_... constants or 0
    @param litems: number of items per line. 0 means auto
    @param align: element alignment
                  - -1: do not align
                  - 0:  automatic alignment
                  - other values: element width

    @return: 1-ok, 0-failure
    """
    return eval_idc("set_array_params(0x%X, 0x%X, %d, %d)"%(ea, flags, litems, align))

AP_ALLOWDUPS    = 0x00000001     # use 'dup' construct
AP_SIGNED       = 0x00000002     # treats numbers as signed
AP_INDEX        = 0x00000004     # display array element indexes as comments
AP_ARRAY        = 0x00000008     # reserved (this flag is not stored in database)
AP_IDXBASEMASK  = 0x000000F0     # mask for number base of the indexes
AP_IDXDEC       = 0x00000000     # display indexes in decimal
AP_IDXHEX       = 0x00000010     # display indexes in hex
AP_IDXOCT       = 0x00000020     # display indexes in octal
AP_IDXBIN       = 0x00000030     # display indexes in binary

op_bin = ida_bytes.op_bin
op_oct = ida_bytes.op_oct
op_dec = ida_bytes.op_dec
op_hex = ida_bytes.op_hex
op_chr = ida_bytes.op_chr


def op_plain_offset(ea, n, base):
    """
    Convert operand to an offset
    (for the explanations of 'ea' and 'n' please see op_bin())

    Example:
    ========

        seg000:2000 dw      1234h

        and there is a segment at paragraph 0x1000 and there is a data item
        within the segment at 0x1234:

        seg000:1234 MyString        db 'Hello, world!',0

        Then you need to specify a linear address of the segment base to
        create a proper offset:

        op_plain_offset(["seg000",0x2000],0,0x10000);

        and you will have:

        seg000:2000 dw      offset MyString

    Motorola 680x0 processor have a concept of "outer offsets".
    If you want to create an outer offset, you need to combine number
    of the operand with the following bit:

    Please note that the outer offsets are meaningful only for
    Motorola 680x0.

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param base: base of the offset as a linear address
        If base == BADADDR then the current operand becomes non-offset
    """
    if base == BADADDR:
        return ida_bytes.clr_op_type(ea, n)
    else:
        return ida_offset.op_plain_offset(ea, n, base)


OPND_OUTER = ida_bytes.OPND_OUTER # outer offset base


op_offset = ida_offset.op_offset


REF_OFF8    = ida_nalt.REF_OFF8    # 8bit full offset
REF_OFF16   = ida_nalt.REF_OFF16   # 16bit full offset
REF_OFF32   = ida_nalt.REF_OFF32   # 32bit full offset
REF_LOW8    = ida_nalt.REF_LOW8    # low 8bits of 16bit offset
REF_LOW16   = ida_nalt.REF_LOW16   # low 16bits of 32bit offset
REF_HIGH8   = ida_nalt.REF_HIGH8   # high 8bits of 16bit offset
REF_HIGH16  = ida_nalt.REF_HIGH16  # high 16bits of 32bit offset
REF_OFF64   = ida_nalt.REF_OFF64   # 64bit full offset
REFINFO_RVA     = 0x10 # based reference (rva)
REFINFO_PASTEND = 0x20 # reference past an item it may point to an nonexistitng
                       # do not destroy alignment dirs
REFINFO_NOBASE  = 0x80 # offset base is a number
                       # that base have be any value
                       # nb: base xrefs are created only if base
                       # points to the middle of a segment
REFINFO_SUBTRACT = 0x0100 # the reference value is subtracted from
                          # the base value instead of (as usual)
                          # being added to it
REFINFO_SIGNEDOP = 0x0200 # the operand value is sign-extended (only
                          # supported for REF_OFF8/16/32/64)

op_seg = ida_bytes.op_seg
op_num = ida_bytes.op_num
op_flt = ida_bytes.op_flt
op_man = ida_bytes.set_forced_operand
toggle_sign = ida_bytes.toggle_sign


def toggle_bnot(ea, n):
    """
    Toggle the bitwise not operator for the operand

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    ida_bytes.toggle_bnot(ea, n)
    return True


op_enum = ida_bytes.op_enum


def op_stroff(ea, n, strid, delta):
    """
    Convert operand to an offset in a structure

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param strid: id of a structure type
    @param delta: struct offset delta. usually 0. denotes the difference
                    between the structure base and the pointer into the structure.

    """
    path = ida_pro.tid_array(1)
    path[0] = strid
    if isinstance(ea, ida_ua.insn_t):
        insn = ea
    else:
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn, ea)
    return ida_bytes.op_stroff(insn, n, path.cast(), 1, delta)


op_stkvar = ida_bytes.op_stkvar


def op_offset_high16(ea, n, target):
    """
    Convert operand to a high offset
    High offset is the upper 16bits of an offset.
    This type is used by TMS320C6 processors (and probably by other
    RISC processors too)

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param target: the full value (all 32bits) of the offset
    """
    return ida_offset.op_offset(ea, n, ida_nalt.REF_HIGH16, target)


def MakeVar(ea):
    pass

# Every anterior/posterior line has its number.
# Anterior  lines have numbers from E_PREV
# Posterior lines have numbers from E_NEXT
E_PREV = ida_lines.E_PREV
E_NEXT = ida_lines.E_NEXT

get_extra_cmt = ida_lines.get_extra_cmt
update_extra_cmt = ida_lines.update_extra_cmt
del_extra_cmt = ida_lines.del_extra_cmt
set_manual_insn = ida_bytes.set_manual_insn
get_manual_insn = ida_bytes.get_manual_insn
patch_dbg_byte = ida_dbg.put_dbg_byte
patch_byte = ida_bytes.patch_byte
patch_word = ida_bytes.patch_word
patch_dword = ida_bytes.patch_dword
patch_qword = ida_bytes.patch_qword


SR_inherit      = 1 # value is inherited from the previous range
SR_user         = 2 # value is specified by the user
SR_auto         = 3 # value is determined by IDA
SR_autostart    = 4 # as SR_auto for segment starting address

def split_sreg_range(ea, reg, value, tag=SR_user):
    """
    Set value of a segment register.

    @param ea: linear address
    @param reg: name of a register, like "cs", "ds", "es", etc.
    @param value: new value of the segment register.
    @param tag: of SR_... constants

    @note: IDA keeps tracks of all the points where segment register change their
           values. This function allows you to specify the correct value of a segment
           register if IDA is not able to find the correct value.
    """
    rnames = [r.casefold() for r in ida_idp.ph_get_regnames()]
    for regno in range(ida_idp.ph_get_reg_first_sreg(), ida_idp.ph_get_reg_last_sreg()+1):
        if rnames[regno]==reg.casefold():
            return ida_segregs.split_sreg_range(ea, regno, value, tag)
    return False


auto_mark_range = ida_auto.auto_mark_range
auto_unmark = ida_auto.auto_unmark


def AutoMark(ea,qtype):
    """
    Plan to analyze an address
    """
    return auto_mark_range(ea,ea+1,qtype)

AU_UNK   = ida_auto.AU_UNK   # make unknown
AU_CODE  = ida_auto.AU_CODE  # convert to instruction
AU_PROC  = ida_auto.AU_PROC  # make function
AU_USED  = ida_auto.AU_USED  # reanalyze
AU_LIBF  = ida_auto.AU_LIBF  # apply a flirt signature (the current signature!)
AU_FINAL = ida_auto.AU_FINAL # coagulate unexplored items


#----------------------------------------------------------------------------
#               P R O D U C E   O U T P U T   F I L E S
#----------------------------------------------------------------------------

def gen_file(filetype, path, ea1, ea2, flags):
    """
    Generate an output file

    @param filetype:  type of output file. One of OFILE_... symbols. See below.
    @param path:  the output file path (will be overwritten!)
    @param ea1:   start address. For some file types this argument is ignored
    @param ea2:   end address. For some file types this argument is ignored
    @param flags: bit combination of GENFLG_...

    @returns: number of the generated lines.
                -1 if an error occurred
                OFILE_EXE: 0-can't generate exe file, 1-ok
    """
    f = ida_diskio.fopenWB(path)

    if f:
        retval = ida_loader.gen_file(filetype, f, ea1, ea2, flags)
        ida_diskio.eclose(f)
        return retval
    else:
        return -1


# output file types:
OFILE_MAP  = ida_loader.OFILE_MAP
OFILE_EXE  = ida_loader.OFILE_EXE
OFILE_IDC  = ida_loader.OFILE_IDC
OFILE_LST  = ida_loader.OFILE_LST
OFILE_ASM  = ida_loader.OFILE_ASM
OFILE_DIF  = ida_loader.OFILE_DIF

# output control flags:
GENFLG_MAPSEG  = ida_loader.GENFLG_MAPSEG  # map: generate map of segments
GENFLG_MAPNAME = ida_loader.GENFLG_MAPNAME # map: include dummy names
GENFLG_MAPDMNG = ida_loader.GENFLG_MAPDMNG # map: demangle names
GENFLG_MAPLOC  = ida_loader.GENFLG_MAPLOC  # map: include local names
GENFLG_IDCTYPE = ida_loader.GENFLG_IDCTYPE # idc: gen only information about types
GENFLG_ASMTYPE = ida_loader.GENFLG_ASMTYPE # asm&lst: gen information about types too
GENFLG_GENHTML = ida_loader.GENFLG_GENHTML # asm&lst: generate html (gui version only)
GENFLG_ASMINC  = ida_loader.GENFLG_ASMINC  # asm&lst: gen information only about types

def gen_flow_graph(outfile, title, ea1, ea2, flags):
    """
    Generate a flow chart GDL file

    @param outfile: output file name. GDL extension will be used
    @param title: graph title
    @param ea1: beginning of the range to flow chart
    @param ea2: end of the range to flow chart.
    @param flags: combination of CHART_... constants

    @note: If ea2 == BADADDR then ea1 is treated as an address within a function.
           That function will be flow charted.
    """
    return ida_gdl.gen_flow_graph(outfile, title, None, ea1, ea2, flags)


CHART_PRINT_NAMES = 0x1000 # print labels for each block?
CHART_GEN_GDL     = 0x4000 # generate .gdl file (file extension is forced to .gdl)
CHART_WINGRAPH    = 0x8000 # call wingraph32 to display the graph
CHART_NOLIBFUNCS  = 0x0400 # don't include library functions in the graph


def gen_simple_call_chart(outfile, title, flags):
    """
    Generate a function call graph GDL file

    @param outfile: output file name. GDL extension will be used
    @param title:   graph title
    @param flags:   combination of CHART_GEN_GDL, CHART_WINGRAPH, CHART_NOLIBFUNCS
    """
    return ida_gdl.gen_simple_call_chart(outfile, "Generating chart", title, flags)


#----------------------------------------------------------------------------
#                 C O M M O N   I N F O R M A T I O N
#----------------------------------------------------------------------------
def idadir():
    """
    Get IDA directory

    This function returns the directory where IDA.EXE resides
    """
    return ida_diskio.idadir("")


get_root_filename = ida_nalt.get_root_filename
get_input_file_path = ida_nalt.get_input_file_path
set_root_filename = ida_nalt.set_root_filename


def get_idb_path():
    """
    Get IDB full path

    This function returns full path of the current IDB database
    """
    return ida_loader.get_path(ida_loader.PATH_TYPE_IDB)


retrieve_input_file_md5 = ida_nalt.retrieve_input_file_md5
get_full_flags = ida_bytes.get_full_flags
get_db_byte = ida_bytes.get_db_byte


def get_bytes(ea, size, use_dbg = False):
    """
    Return the specified number of bytes of the program

    @param ea: linear address

    @param size: size of buffer in normal 8-bit bytes

    @param use_dbg: if True, use debugger memory, otherwise just the database

    @return: None on failure
             otherwise a string containing the read bytes
    """
    if use_dbg:
        return ida_idd.dbg_read_memory(ea, size)
    else:
        return ida_bytes.get_bytes(ea, size)


get_wide_byte = ida_bytes.get_wide_byte


def __DbgValue(ea, len):
    if len not in ida_idaapi.__struct_unpack_table:
        return None
    r = ida_idd.dbg_read_memory(ea, len)
    return None if r is None else struct.unpack((">" if ida_ida.cvar.inf.is_be() else "<") + ida_idaapi.__struct_unpack_table[len][1], r)[0]


def read_dbg_byte(ea):
    """
    Get value of program byte using the debugger memory

    @param ea: linear address
    @return: The value or None on failure.
    """
    return __DbgValue(ea, 1)


def read_dbg_word(ea):
    """
    Get value of program word using the debugger memory

    @param ea: linear address
    @return: The value or None on failure.
    """
    return __DbgValue(ea, 2)


def read_dbg_dword(ea):
    """
    Get value of program double-word using the debugger memory

    @param ea: linear address
    @return: The value or None on failure.
    """
    return __DbgValue(ea, 4)


def read_dbg_qword(ea):
    """
    Get value of program quadro-word using the debugger memory

    @param ea: linear address
    @return: The value or None on failure.
    """
    return __DbgValue(ea, 8)


read_dbg_memory = ida_idd.dbg_read_memory


def write_dbg_memory(ea, data):
    """
    Write to debugger memory.

    @param ea: linear address
    @param data: string to write
    @return: number of written bytes (-1 - network/debugger error)

    Thread-safe function (may be called only from the main thread and debthread)
    """
    __warn_once_deprecated_proto_confusion("write_dbg_memory", "ida_dbg.write_dbg_memory")
    if not ida_dbg.dbg_can_query():
        return -1
    elif len(data) > 0:
        return ida_idd.dbg_write_memory(ea, data)


get_original_byte = ida_bytes.get_original_byte
get_wide_word = ida_bytes.get_wide_word
get_wide_dword = ida_bytes.get_wide_dword
get_qword = ida_bytes.get_qword


def GetFloat(ea):
    """
    Get value of a floating point number (4 bytes)
    This function assumes number stored using IEEE format
    and in the same endianness as integers.

    @param ea: linear address

    @return: float
    """
    tmp = struct.pack("I", get_wide_dword(ea))
    return struct.unpack("f", tmp)[0]


def GetDouble(ea):
    """
    Get value of a floating point number (8 bytes)
    This function assumes number stored using IEEE format
    and in the same endianness as integers.

    @param ea: linear address

    @return: double
    """
    tmp = struct.pack("Q", get_qword(ea))
    return struct.unpack("d", tmp)[0]


def get_name_ea_simple(name):
    """
    Get linear address of a name

    @param name: name of program byte

    @return: address of the name
             BADADDR - No such name
    """
    return ida_name.get_name_ea(BADADDR, name)


get_name_ea = ida_name.get_name_ea


def get_segm_by_sel(base):
    """
    Get segment by segment base

    @param base: segment base paragraph or selector

    @return: linear address of the start of the segment or BADADDR
             if no such segment
    """
    sel = ida_segment.find_selector(base)
    seg = ida_segment.get_segm_by_sel(sel)

    if seg:
        return seg.start_ea
    else:
        return BADADDR


get_screen_ea = ida_kernwin.get_screen_ea


def get_curline():
    """
    Get the disassembly line at the cursor

    @return: string
    """
    return ida_lines.tag_remove(ida_kernwin.get_curline())


def read_selection_start():
    """
    Get start address of the selected range
    returns BADADDR - the user has not selected an range
    """
    selection, startaddr, endaddr = ida_kernwin.read_range_selection(None)

    if selection == 1:
        return startaddr
    else:
        return BADADDR


def read_selection_end():
    """
    Get end address of the selected range

    @return: BADADDR - the user has not selected an range
    """
    selection, startaddr, endaddr = ida_kernwin.read_range_selection(None)

    if selection == 1:
        return endaddr
    else:
        return BADADDR


def get_sreg(ea, reg):
    """
    Get value of segment register at the specified address

    @param ea: linear address
    @param reg: name of segment register

    @return: the value of the segment register or -1 on error

    @note: The segment registers in 32bit program usually contain selectors,
           so to get paragraph pointed to by the segment register you need to
           call sel2para() function.
    """
    reg = ida_idp.str2reg(reg);
    if reg >= 0:
        return ida_segregs.get_sreg(ea, reg)
    else:
        return -1

next_addr = ida_bytes.next_addr
prev_addr = ida_bytes.prev_addr


def next_head(ea, maxea=BADADDR):
    """
    Get next defined item (instruction or data) in the program

    @param ea: linear address to start search from
    @param maxea: the search will stop at the address
        maxea is not included in the search range

    @return: BADADDR - no (more) defined items
    """
    return ida_bytes.next_head(ea, maxea)


def prev_head(ea, minea=0):
    """
    Get previous defined item (instruction or data) in the program

    @param ea: linear address to start search from
    @param minea: the search will stop at the address
            minea is included in the search range

    @return: BADADDR - no (more) defined items
    """
    return ida_bytes.prev_head(ea, minea)


next_not_tail = ida_bytes.next_not_tail
prev_not_tail = ida_bytes.prev_not_tail
get_item_head = ida_bytes.get_item_head
get_item_end = ida_bytes.get_item_end


def get_item_size(ea):
    """
    Get size of instruction or data item in bytes

    @param ea: linear address

    @return: 1..n
    """
    return ida_bytes.get_item_end(ea) - ea


def func_contains(func_ea, ea):
    """
    Does the given function contain the given address?

    @param func_ea: any address belonging to the function
    @param ea: linear address

    @return:  success
    """
    func = ida_funcs.get_func(func_ea)

    if func:
        return ida_funcs.func_contains(func, ea)
    return False


GN_VISIBLE = ida_name.GN_VISIBLE     # replace forbidden characters by SUBSTCHAR
GN_COLORED = ida_name.GN_COLORED     # return colored name
GN_DEMANGLED = ida_name.GN_DEMANGLED # return demangled name
GN_STRICT = ida_name.GN_STRICT       # fail if cannot demangle
GN_SHORT = ida_name.GN_SHORT         # use short form of demangled name
GN_LONG = ida_name.GN_LONG           # use long form of demangled name
GN_LOCAL = ida_name.GN_LOCAL         # try to get local name first; if failed, get global
GN_ISRET = ida_name.GN_ISRET         # for dummy names: use retloc
GN_NOT_ISRET = ida_name.GN_NOT_ISRET # for dummy names: do not use retloc


calc_gtn_flags = ida_name.calc_gtn_flags


def get_name(ea, gtn_flags=0):
    """
    Get name at the specified address

    @param ea: linear address
    @param gtn_flags: how exactly the name should be retrieved.
                      combination of GN_ bits

    @return: "" - byte has no name
    """
    return ida_name.get_ea_name(ea, gtn_flags)


def demangle_name(name, disable_mask):
    """
    demangle_name a name

    @param name: name to demangle
    @param disable_mask: a mask that tells how to demangle the name
            it is a good idea to get this mask using
            get_inf_attr(INF_SHORT_DN) or get_inf_attr(INF_LONG_DN)

    @return: a demangled name
        If the input name cannot be demangled, returns None
    """
    return ida_name.demangle_name(name, disable_mask, ida_name.DQT_FULL)


def generate_disasm_line(ea, flags):
    """
    Get disassembly line

    @param ea: linear address of instruction

    @param flags: combination of the GENDSM_ flags, or 0

    @return: "" - could not decode instruction at the specified location

    @note: this function may not return exactly the same mnemonics
           as you see on the screen.
    """
    text = ida_lines.generate_disasm_line(ea, flags)
    if text:
        return ida_lines.tag_remove(text)
    else:
        return ""

# flags for generate_disasm_line
# generate a disassembly line as if
# there is an instruction at 'ea'
GENDSM_FORCE_CODE = ida_lines.GENDSM_FORCE_CODE

# if the instruction consists of several lines,
# produce all of them (useful for parallel instructions)
GENDSM_MULTI_LINE = ida_lines.GENDSM_MULTI_LINE

def GetDisasm(ea):
    """
    Get disassembly line

    @param ea: linear address of instruction

    @return: "" - could not decode instruction at the specified location

    @note: this function may not return exactly the same mnemonics
           as you see on the screen.
    """
    return generate_disasm_line(ea, 0)

def print_insn_mnem(ea):
    """
    Get instruction mnemonics

    @param ea: linear address of instruction

    @return: "" - no instruction at the specified location

    @note: this function may not return exactly the same mnemonics
    as you see on the screen.
    """
    res = ida_ua.ua_mnem(ea)

    if not res:
        return ""
    else:
        return res


def print_operand(ea, n):
    """
    Get operand of an instruction or data

    @param ea: linear address of the item
    @param n: number of operand:
        0 - the first operand
        1 - the second operand

    @return: the current text representation of operand or ""
    """

    res = ida_ua.print_operand(ea, n)

    if not res:
        return ""
    else:
        return ida_lines.tag_remove(res)


def get_operand_type(ea, n):
    """
    Get type of instruction operand

    @param ea: linear address of instruction
    @param n: number of operand:
        0 - the first operand
        1 - the second operand

    @return: any of o_* constants or -1 on error
    """
    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, ea)
    return -1 if inslen == 0 else insn.ops[n].type


o_void     = ida_ua.o_void      # No Operand                           ----------
o_reg      = ida_ua.o_reg       # General Register (al,ax,es,ds...)    reg
o_mem      = ida_ua.o_mem       # Direct Memory Reference  (DATA)      addr
o_phrase   = ida_ua.o_phrase    # Memory Ref [Base Reg + Index Reg]    phrase
o_displ    = ida_ua.o_displ     # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
o_imm      = ida_ua.o_imm       # Immediate Value                      value
o_far      = ida_ua.o_far       # Immediate Far Address  (CODE)        addr
o_near     = ida_ua.o_near      # Immediate Near Address (CODE)        addr
o_idpspec0 = ida_ua.o_idpspec0  # Processor specific type
o_idpspec1 = ida_ua.o_idpspec1  # Processor specific type
o_idpspec2 = ida_ua.o_idpspec2  # Processor specific type
o_idpspec3 = ida_ua.o_idpspec3  # Processor specific type
o_idpspec4 = ida_ua.o_idpspec4  # Processor specific type
o_idpspec5 = ida_ua.o_idpspec5  # Processor specific type
                                # There can be more processor specific types

# x86
o_trreg  =       ida_ua.o_idpspec0      # trace register
o_dbreg  =       ida_ua.o_idpspec1      # debug register
o_crreg  =       ida_ua.o_idpspec2      # control register
o_fpreg  =       ida_ua.o_idpspec3      # floating point register
o_mmxreg  =      ida_ua.o_idpspec4      # mmx register
o_xmmreg  =      ida_ua.o_idpspec5      # xmm register

# arm
o_reglist  =     ida_ua.o_idpspec1      # Register list (for LDM/STM)
o_creglist  =    ida_ua.o_idpspec2      # Coprocessor register list (for CDP)
o_creg  =        ida_ua.o_idpspec3      # Coprocessor register (for LDC/STC)
o_fpreglist  =   ida_ua.o_idpspec4      # Floating point register list
o_text  =        ida_ua.o_idpspec5      # Arbitrary text stored in the operand
o_cond  =        (ida_ua.o_idpspec5+1)  # ARM condition as an operand

# ppc
o_spr  =         ida_ua.o_idpspec0      # Special purpose register
o_twofpr  =      ida_ua.o_idpspec1      # Two FPRs
o_shmbme  =      ida_ua.o_idpspec2      # SH & MB & ME
o_crf  =         ida_ua.o_idpspec3      # crfield      x.reg
o_crb  =         ida_ua.o_idpspec4      # crbit        x.reg
o_dcr  =         ida_ua.o_idpspec5      # Device control register

def get_operand_value(ea, n):
    """
    Get number used in the operand

    This function returns an immediate number used in the operand

    @param ea: linear address of instruction
    @param n: the operand number

    @return: value
        operand is an immediate value  => immediate value
        operand has a displacement     => displacement
        operand is a direct memory ref => memory address
        operand is a register          => register number
        operand is a register phrase   => phrase number
        otherwise                      => -1
    """
    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, ea)
    if inslen == 0:
        return -1
    op = insn.ops[n]
    if not op:
        return -1

    if op.type in [ ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near, ida_ua.o_displ ]:
        value = op.addr
    elif op.type == ida_ua.o_reg:
        value = op.reg
    elif op.type == ida_ua.o_imm:
        value = op.value
    elif op.type == ida_ua.o_phrase:
        value = op.phrase
    else:
        value = -1
    return value


GetCommentEx = ida_bytes.get_cmt
get_cmt = GetCommentEx
get_forced_operand = ida_bytes.get_forced_operand

BPU_1B = ida_nalt.BPU_1B
BPU_2B = ida_nalt.BPU_2B
BPU_4B = ida_nalt.BPU_4B

STRWIDTH_1B   = ida_nalt.STRWIDTH_1B
STRWIDTH_2B   = ida_nalt.STRWIDTH_2B
STRWIDTH_4B   = ida_nalt.STRWIDTH_4B
STRWIDTH_MASK = ida_nalt.STRWIDTH_MASK

STRLYT_TERMCHR = ida_nalt.STRLYT_TERMCHR
STRLYT_PASCAL1 = ida_nalt.STRLYT_PASCAL1
STRLYT_PASCAL2 = ida_nalt.STRLYT_PASCAL2
STRLYT_PASCAL4 = ida_nalt.STRLYT_PASCAL4
STRLYT_MASK    = ida_nalt.STRLYT_MASK
STRLYT_SHIFT   = ida_nalt.STRLYT_SHIFT

# Character-terminated string. The termination characters
# are kept in the next bytes of string type.
STRTYPE_TERMCHR   = ida_nalt.STRTYPE_TERMCHR
# C-style string.
STRTYPE_C         = ida_nalt.STRTYPE_C
# Zero-terminated 16bit chars
STRTYPE_C_16      = ida_nalt.STRTYPE_C_16
# Zero-terminated 32bit chars
STRTYPE_C_32      = ida_nalt.STRTYPE_C_32
# Pascal-style, one-byte length prefix
STRTYPE_PASCAL    = ida_nalt.STRTYPE_PASCAL
# Pascal-style, 16bit chars, one-byte length prefix
STRTYPE_PASCAL_16 = ida_nalt.STRTYPE_PASCAL_16
# Pascal-style, two-byte length prefix
STRTYPE_LEN2      = ida_nalt.STRTYPE_LEN2
# Pascal-style, 16bit chars, two-byte length prefix
STRTYPE_LEN2_16   = ida_nalt.STRTYPE_LEN2_16
# Pascal-style, four-byte length prefix
STRTYPE_LEN4      = ida_nalt.STRTYPE_LEN4
# Pascal-style, 16bit chars, four-byte length prefix
STRTYPE_LEN4_16   = ida_nalt.STRTYPE_LEN4_16

# alias
STRTYPE_C16       = STRTYPE_C_16

def get_strlit_contents(ea, length = -1, strtype = STRTYPE_C):
    """
    Get string contents
    @param ea: linear address
    @param length: string length. -1 means to calculate the max string length
    @param strtype: the string type (one of STRTYPE_... constants)

    @return: string contents or empty string
    """
    if length == -1:
        length = ida_bytes.get_max_strlit_length(ea, strtype, ida_bytes.ALOPT_IGNHEADS)

    return ida_bytes.get_strlit_contents(ea, length, strtype)


def get_str_type(ea):
    """
    Get string type

    @param ea: linear address

    @return: One of STRTYPE_... constants
    """
    flags = ida_bytes.get_flags(ea)
    if ida_bytes.is_strlit(flags):
        oi = ida_nalt.opinfo_t()
        if ida_bytes.get_opinfo(oi, ea, 0, flags):
            return oi.strtype

#      The following functions search for the specified byte
#          ea - address to start from
#          flag is combination of the following bits

#      returns BADADDR - not found
find_suspop  = ida_search.find_suspop
find_code    = ida_search.find_code
find_data    = ida_search.find_data
find_unknown = ida_search.find_unknown
find_defined = ida_search.find_defined
find_imm     = ida_search.find_imm

SEARCH_UP       = ida_search.SEARCH_UP       # search backward
SEARCH_DOWN     = ida_search.SEARCH_DOWN     # search forward
SEARCH_NEXT     = ida_search.SEARCH_NEXT     # start the search at the next/prev item
                                             # useful only for find_text() and find_binary()
SEARCH_CASE     = ida_search.SEARCH_CASE     # search case-sensitive
                                             # (only for bin&txt search)
SEARCH_REGEX    = ida_search.SEARCH_REGEX    # enable regular expressions (only for text)
SEARCH_NOBRK    = ida_search.SEARCH_NOBRK    # don't test ctrl-break
SEARCH_NOSHOW   = ida_search.SEARCH_NOSHOW   # don't display the search progress


def find_text(ea, flag, y, x, searchstr):
    __warn_once_deprecated_proto_confusion("find_text", "ida_search.find_text")
    return ida_search.find_text(ea, y, x, searchstr, flag)


def find_binary(ea, flag, searchstr, radix=16):
    __warn_once_deprecated_proto_confusion("find_binary", "ida_search.find_binary")
    endea = flag & 1 and ida_ida.cvar.inf.max_ea or ida_ida.cvar.inf.min_ea
    return ida_search.find_binary(ea, endea, searchstr, radix, flag)


#----------------------------------------------------------------------------
#       G L O B A L   S E T T I N G S   M A N I P U L A T I O N
#----------------------------------------------------------------------------
def process_config_line(directive):
    """
    Obsolete. Please use ida_idp.process_config_directive().
    """
    return eval_idc('process_config_directive("%s")' % ida_kernwin.str2user(directive))


# The following functions allow you to set/get common parameters.
# Please note that not all parameters can be set directly.



INF_VERSION    = 0            # short;   Version of database
INF_PROCNAME   = 1            # char[8]; Name of current processor
INF_GENFLAGS   = 2            # ushort;  General flags:
INF_LFLAGS     = 3            # uint32;  IDP-dependent flags

INF_DATABASE_CHANGE_COUNT= 4  # uint32; database change counter; keeps track of byte and segment modifications
INF_CHANGE_COUNTER=INF_DATABASE_CHANGE_COUNT

INF_FILETYPE   = 5            # short;   type of input file (see ida.hpp)
FT_EXE_OLD     = 0            #              MS DOS EXE File (obsolete)
FT_COM_OLD     = 1            #              MS DOS COM File (obsolete)
FT_BIN         = 2            #              Binary File
FT_DRV         = 3            #              MS DOS Driver
FT_WIN         = 4            #              New Executable (NE)
FT_HEX         = 5            #              Intel Hex Object File
FT_MEX         = 6            #              MOS Technology Hex Object File
FT_LX          = 7            #              Linear Executable (LX)
FT_LE          = 8            #              Linear Executable (LE)
FT_NLM         = 9            #              Netware Loadable Module (NLM)
FT_COFF        = 10           #              Common Object File Format (COFF)
FT_PE          = 11           #              Portable Executable (PE)
FT_OMF         = 12           #              Object Module Format
FT_SREC        = 13           #              R-records
FT_ZIP         = 14           #              ZIP file (this file is never loaded to IDA database)
FT_OMFLIB      = 15           #              Library of OMF Modules
FT_AR          = 16           #              ar library
FT_LOADER      = 17           #              file is loaded using LOADER DLL
FT_ELF         = 18           #              Executable and Linkable Format (ELF)
FT_W32RUN      = 19           #              Watcom DOS32 Extender (W32RUN)
FT_AOUT        = 20           #              Linux a.out (AOUT)
FT_PRC         = 21           #              PalmPilot program file
FT_EXE         = 22           #              MS DOS EXE File
FT_COM         = 23           #              MS DOS COM File
FT_AIXAR       = 24           #              AIX ar library
FT_MACHO       = 25           #              Mac OS X Mach-O file
INF_OSTYPE     = 6            # short;   FLIRT: OS type the program is for
OSTYPE_MSDOS= 0x0001
OSTYPE_WIN  = 0x0002
OSTYPE_OS2  = 0x0004
OSTYPE_NETW = 0x0008
INF_APPTYPE    = 7            # short;   FLIRT: Application type
APPT_CONSOLE= 0x0001          #              console
APPT_GRAPHIC= 0x0002          #              graphics
APPT_PROGRAM= 0x0004          #              EXE
APPT_LIBRARY= 0x0008          #              DLL
APPT_DRIVER = 0x0010          #              DRIVER
APPT_1THREAD= 0x0020          #              Singlethread
APPT_MTHREAD= 0x0040          #              Multithread
APPT_16BIT  = 0x0080          #              16 bit application
APPT_32BIT  = 0x0100          #              32 bit application
INF_ASMTYPE    = 8            # char;    target assembler number (0..n)
INF_SPECSEGS   = 9

INF_AF         = 10           # uint32;   Analysis flags:

def _import_module_flag_sets(module, prefixes):
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    for prefix in prefixes:
        for key in dir(module):
            if key.startswith(prefix):
                value = getattr(module, key)
                if isinstance(value, ida_idaapi.integer_types):
                    globals()[key] = value
_import_module_flag_sets(
    ida_ida,
    [
        "INFFL_",
        "LFLG_",
        "IDB_",
        "AF_",
        "AF2_",
        "SW_",
        "NM_",
        "DEMNAM_",
        "LN_",
        "OFLG_",
        "SCF_",
        "LMT_",
        "PREF_",
        "STRF_",
        "ABI_",
    ])

INF_AF2        = 11           # uint32;  Analysis flags 2

INF_BASEADDR   = 12           # uval_t;  base paragraph of the program
INF_START_SS   = 13           # int32;   value of SS at the start
INF_START_CS   = 14           # int32;   value of CS at the start
INF_START_IP   = 15           # ea_t;    IP register value at the start of
                              #          program execution
INF_START_EA   = 16           # ea_t;    Linear address of program entry point
INF_START_SP   = 17           # ea_t;    SP register value at the start of
                              #          program execution
INF_MAIN       = 18           # ea_t;    address of main()
INF_MIN_EA     = 19           # ea_t;    The lowest address used
                              #          in the program
INF_MAX_EA     = 20           # ea_t;    The highest address used
                              #          in the program - 1
INF_OMIN_EA    = 21
INF_OMAX_EA    = 22
INF_LOWOFF     = 23           # ea_t;    low limit of voids
INF_LOW_OFF=INF_LOWOFF
INF_HIGHOFF    = 24           # ea_t;    high limit of voids
INF_HIGH_OFF=INF_HIGHOFF
INF_MAXREF     = 25           # uval_t;  max xref depth
INF_PRIVRANGE_START_EA = 27   # uval_t; Range of addresses reserved for internal use.
INF_START_PRIVRANGE=INF_PRIVRANGE_START_EA
INF_PRIVRANGE_END_EA = 28     # uval_t; Initially (MAXADDR, MAXADDR+0x100000)
INF_END_PRIVRANGE=INF_PRIVRANGE_END_EA

INF_NETDELTA   = 29           # sval_t; Delta value to be added to all adresses for mapping to netnodes.
                              # Initially 0.
# CROSS REFERENCES
INF_XREFNUM    = 30           # char;    Number of references to generate
                              #          0 - xrefs won't be generated at all
INF_TYPE_XREFNUM = 31        # char;    Number of references to generate
                              #          in the struct & enum windows
                              #          0 - xrefs won't be generated at all
INF_TYPE_XREFS=INF_TYPE_XREFNUM
INF_REFCMTNUM  = 32          # uchar; number of comment lines to
                              #        generate for refs to ASCII
                              #        string or demangled name
                              #        0 - such comments won't be
                              #        generated at all
INF_REFCMTS=INF_REFCMTNUM
INF_XREFFLAG   = 33          # char;    xrefs representation:
INF_XREFS=INF_XREFFLAG

# NAMES
INF_MAX_AUTONAME_LEN = 34     # ushort;  max name length (without zero byte)
INF_NAMETYPE   = 35           # char;    dummy names represenation type
INF_SHORT_DEMNAMES = 36      # int32;   short form of demangled names
INF_SHORT_DN=INF_SHORT_DEMNAMES
INF_LONG_DEMNAMES = 37       # int32;   long form of demangled names
                              #          see demangle.h for definitions
INF_LONG_DN=INF_LONG_DEMNAMES
INF_DEMNAMES   = 38           # char;    display demangled names as:
INF_LISTNAMES  = 39           # uchar;   What names should be included in the list?

# DISASSEMBLY LISTING DETAILS
INF_INDENT     = 40           # char;    Indention for instructions
INF_CMT_INDENT = 41           # char;    Indention for comments
INF_COMMENT    = 41           # for compatibility
INF_MARGIN     = 42           # ushort;  max length of data lines
INF_LENXREF    = 43           # ushort;  max length of line with xrefs
INF_OUTFLAGS   = 44           # uint32;  output flags
INF_CMTFLG     = 45           # char;    comments:
INF_CMTFLAG=INF_CMTFLG
INF_LIMITER    = 46           # char;    Generate borders?
INF_BORDER=INF_LIMITER
INF_BIN_PREFIX_SIZE = 47     # short;   # of instruction bytes to show
                              #          in line prefix
INF_BINPREF=INF_BIN_PREFIX_SIZE
INF_PREFFLAG   = 48           # char;    line prefix type:

# STRING LITERALS
INF_STRLIT_FLAGS= 49          # uchar;   string literal flags
INF_STRLIT_BREAK= 50         # char;    string literal line break symbol
INF_STRLIT_ZEROES= 51        # char;    leading zeroes
INF_STRTYPE    = 52          # int32;   current ascii string type
                              #          is considered as several bytes:
                              #      low byte:

INF_STRLIT_PREF  = 53         # char[16];ASCII names prefix
INF_STRLIT_SERNUM= 54         # uint32;  serial number

# DATA ITEMS
INF_DATATYPES    = 55         # int32;   data types allowed in data carousel

# COMPILER
INF_CC_ID        = 57         # uchar;   compiler
COMP_MASK    = 0x0F           #              mask to apply to get the pure compiler id
COMP_UNK     = 0x00           # Unknown
COMP_MS      = 0x01           # Visual C++
COMP_BC      = 0x02           # Borland C++
COMP_WATCOM  = 0x03           # Watcom C++
COMP_GNU     = 0x06           # GNU C++
COMP_VISAGE  = 0x07           # Visual Age C++
COMP_BP      = 0x08           # Delphi
INF_CC_CM        = 58         # uchar;  memory model & calling convention
INF_CC_SIZE_I    = 59         # uchar;  sizeof(int)
INF_CC_SIZE_B    = 60         # uchar;  sizeof(bool)
INF_CC_SIZE_E    = 61         # uchar;  sizeof(enum)
INF_CC_DEFALIGN  = 62         # uchar;  default alignment
INF_CC_SIZE_S    = 63
INF_CC_SIZE_L    = 64
INF_CC_SIZE_LL   = 65
INF_CC_SIZE_LDBL = 66         # uchar;  sizeof(long double)
INF_COMPILER    = INF_CC_ID
INF_MODEL       = INF_CC_CM
INF_SIZEOF_INT  = INF_CC_SIZE_I
INF_SIZEOF_BOOL = INF_CC_SIZE_B
INF_SIZEOF_ENUM = INF_CC_SIZE_E
INF_SIZEOF_ALGN = INF_CC_DEFALIGN
INF_SIZEOF_SHORT= INF_CC_SIZE_S
INF_SIZEOF_LONG = INF_CC_SIZE_L
INF_SIZEOF_LLONG= INF_CC_SIZE_LL
INF_SIZEOF_LDBL = INF_CC_SIZE_LDBL
INF_ABIBITS= 67               # uint32; ABI features
INF_APPCALL_OPTIONS= 68       # uint32; appcall options

_INF_attrs_accessors = {
    INF_ABIBITS               : (ida_ida.inf_get_abibits,               ida_ida.inf_set_abibits),
    INF_AF                    : (ida_ida.inf_get_af,                    ida_ida.inf_set_af),
    INF_AF2                   : (ida_ida.inf_get_af2,                   ida_ida.inf_set_af2),
    INF_APPCALL_OPTIONS       : (ida_ida.inf_get_appcall_options,       ida_ida.inf_set_appcall_options),
    INF_APPTYPE               : (ida_ida.inf_get_apptype,               ida_ida.inf_set_apptype),
    INF_ASMTYPE               : (ida_ida.inf_get_asmtype,               ida_ida.inf_set_asmtype),
    INF_BASEADDR              : (ida_ida.inf_get_baseaddr,              ida_ida.inf_set_baseaddr),
    INF_BIN_PREFIX_SIZE       : (ida_ida.inf_get_bin_prefix_size,       ida_ida.inf_set_bin_prefix_size),
    INF_CC_CM                 : (ida_ida.inf_get_cc_cm,                 ida_ida.inf_set_cc_cm),
    INF_CC_DEFALIGN           : (ida_ida.inf_get_cc_defalign,           ida_ida.inf_set_cc_defalign),
    INF_CC_ID                 : (ida_ida.inf_get_cc_id,                 ida_ida.inf_set_cc_id),
    INF_CC_SIZE_B             : (ida_ida.inf_get_cc_size_b,             ida_ida.inf_set_cc_size_b),
    INF_CC_SIZE_E             : (ida_ida.inf_get_cc_size_e,             ida_ida.inf_set_cc_size_e),
    INF_CC_SIZE_I             : (ida_ida.inf_get_cc_size_i,             ida_ida.inf_set_cc_size_i),
    INF_CC_SIZE_L             : (ida_ida.inf_get_cc_size_l,             ida_ida.inf_set_cc_size_l),
    INF_CC_SIZE_LDBL          : (ida_ida.inf_get_cc_size_ldbl,          ida_ida.inf_set_cc_size_ldbl),
    INF_CC_SIZE_LL            : (ida_ida.inf_get_cc_size_ll,            ida_ida.inf_set_cc_size_ll),
    INF_CC_SIZE_S             : (ida_ida.inf_get_cc_size_s,             ida_ida.inf_set_cc_size_s),
    INF_CMTFLAG               : (ida_ida.inf_get_cmtflg,                ida_ida.inf_set_cmtflg),
    INF_CMT_INDENT            : (ida_ida.inf_get_cmt_indent,            ida_ida.inf_set_cmt_indent),
    INF_DATABASE_CHANGE_COUNT : (ida_ida.inf_get_database_change_count, ida_ida.inf_set_database_change_count),
    INF_DATATYPES             : (ida_ida.inf_get_datatypes,             ida_ida.inf_set_datatypes),
    INF_DEMNAMES              : (ida_ida.inf_get_demnames,              ida_ida.inf_set_demnames),
    INF_END_PRIVRANGE         : (ida_ida.inf_get_privrange_end_ea,      ida_ida.inf_set_privrange_end_ea),
    INF_FILETYPE              : (ida_ida.inf_get_filetype,              ida_ida.inf_set_filetype),
    INF_GENFLAGS              : (ida_ida.inf_get_genflags,              ida_ida.inf_set_genflags),
    INF_HIGHOFF               : (ida_ida.inf_get_highoff,               ida_ida.inf_set_highoff),
    INF_INDENT                : (ida_ida.inf_get_indent,                ida_ida.inf_set_indent),
    INF_LENXREF               : (ida_ida.inf_get_lenxref,               ida_ida.inf_set_lenxref),
    INF_LFLAGS                : (ida_ida.inf_get_lflags,                ida_ida.inf_set_lflags),
    INF_LIMITER               : (ida_ida.inf_get_limiter,               ida_ida.inf_set_limiter),
    INF_LISTNAMES             : (ida_ida.inf_get_listnames,             ida_ida.inf_set_listnames),
    INF_LONG_DEMNAMES         : (ida_ida.inf_get_long_demnames,         ida_ida.inf_set_long_demnames),
    INF_LOWOFF                : (ida_ida.inf_get_lowoff,                ida_ida.inf_set_lowoff),
    INF_MAIN                  : (ida_ida.inf_get_main,                  ida_ida.inf_set_main),
    INF_MARGIN                : (ida_ida.inf_get_margin,                ida_ida.inf_set_margin),
    INF_MAXREF                : (ida_ida.inf_get_maxref,                ida_ida.inf_set_maxref),
    INF_MAX_AUTONAME_LEN      : (ida_ida.inf_get_max_autoname_len,      ida_ida.inf_set_max_autoname_len),
    INF_MAX_EA                : (ida_ida.inf_get_max_ea,                ida_ida.inf_set_max_ea),
    INF_MIN_EA                : (ida_ida.inf_get_min_ea,                ida_ida.inf_set_min_ea),
    INF_MODEL                 : (ida_ida.inf_get_cc_cm,                 ida_ida.inf_set_cc_cm),
    INF_NAMETYPE              : (ida_ida.inf_get_nametype,              ida_ida.inf_set_nametype),
    INF_NETDELTA              : (ida_ida.inf_get_netdelta,              ida_ida.inf_set_netdelta),
    INF_OMAX_EA               : (ida_ida.inf_get_omax_ea,               ida_ida.inf_set_omax_ea),
    INF_OMIN_EA               : (ida_ida.inf_get_omin_ea,               ida_ida.inf_set_omin_ea),
    INF_OSTYPE                : (ida_ida.inf_get_ostype,                ida_ida.inf_set_ostype),
    INF_OUTFLAGS              : (ida_ida.inf_get_outflags,              ida_ida.inf_set_outflags),
    INF_PREFFLAG              : (ida_ida.inf_get_prefflag,              ida_ida.inf_set_prefflag),
    INF_PRIVRANGE_END_EA      : (ida_ida.inf_get_privrange_end_ea,      ida_ida.inf_set_privrange_end_ea),
    INF_PRIVRANGE_START_EA    : (ida_ida.inf_get_privrange_start_ea,    ida_ida.inf_set_privrange_start_ea),
    INF_PROCNAME              : (ida_ida.inf_get_procname,              ida_ida.inf_set_procname),
    INF_REFCMTNUM             : (ida_ida.inf_get_refcmtnum,             ida_ida.inf_set_refcmtnum),
    INF_SHORT_DEMNAMES        : (ida_ida.inf_get_short_demnames,        ida_ida.inf_set_short_demnames),
    INF_SPECSEGS              : (ida_ida.inf_get_specsegs,              ida_ida.inf_set_specsegs),
    INF_START_CS              : (ida_ida.inf_get_start_cs,              ida_ida.inf_set_start_cs),
    INF_START_EA              : (ida_ida.inf_get_start_ea,              ida_ida.inf_set_start_ea),
    INF_START_IP              : (ida_ida.inf_get_start_ip,              ida_ida.inf_set_start_ip),
    INF_START_PRIVRANGE       : (ida_ida.inf_get_privrange_start_ea,    ida_ida.inf_set_privrange_start_ea),
    INF_START_SP              : (ida_ida.inf_get_start_sp,              ida_ida.inf_set_start_sp),
    INF_START_SS              : (ida_ida.inf_get_start_ss,              ida_ida.inf_set_start_ss),
    INF_STRLIT_BREAK          : (ida_ida.inf_get_strlit_break,          ida_ida.inf_set_strlit_break),
    INF_STRLIT_FLAGS          : (ida_ida.inf_get_strlit_flags,          ida_ida.inf_set_strlit_flags),
    INF_STRLIT_PREF           : (ida_ida.inf_get_strlit_pref,           ida_ida.inf_set_strlit_pref),
    INF_STRLIT_SERNUM         : (ida_ida.inf_get_strlit_sernum,         ida_ida.inf_set_strlit_sernum),
    INF_STRLIT_ZEROES         : (ida_ida.inf_get_strlit_zeroes,         ida_ida.inf_set_strlit_zeroes),
    INF_STRTYPE               : (ida_ida.inf_get_strtype,               ida_ida.inf_set_strtype),
    INF_TYPE_XREFNUM          : (ida_ida.inf_get_type_xrefnum,          ida_ida.inf_set_type_xrefnum),
    INF_VERSION               : (ida_ida.inf_get_version,               ida_ida.inf_set_version),
    INF_XREFFLAG              : (ida_ida.inf_get_xrefflag,              ida_ida.inf_set_xrefflag),
    INF_XREFNUM               : (ida_ida.inf_get_xrefnum,               ida_ida.inf_set_xrefnum),
}

def get_inf_attr(attr):
    """
    Deprecated. Please ida_ida.inf_get_* instead.
    """
    return _INF_attrs_accessors[attr][0]()

def set_inf_attr(attr, value):
    """
    Deprecated. Please ida_ida.inf_set_* instead.
    """
    _INF_attrs_accessors[attr][1](value)
    return 1

set_processor_type  = ida_idp.set_processor_type

SETPROC_IDB              = ida_idp.SETPROC_IDB
SETPROC_LOADER           = ida_idp.SETPROC_LOADER
SETPROC_LOADER_NON_FATAL = ida_idp.SETPROC_LOADER_NON_FATAL
SETPROC_USER             = ida_idp.SETPROC_USER

def SetPrcsr(processor): return set_processor_type(processor, SETPROC_USER)

def get_processor_name():
    """
    Get name of the current processor
    @return: processor name
    """
    return ida_ida.inf_get_procname()

set_target_assembler = ida_idp.set_target_assembler


def batch(batch):
    """
    Enable/disable batch mode of operation

    @param batch: batch mode
            0 - ida will display dialog boxes and wait for the user input
            1 - ida will not display dialog boxes, warnings, etc.

    @return: old balue of batch flag
    """
    batch_prev = ida_kernwin.cvar.batch
    ida_kernwin.cvar.batch = batch
    return batch_prev


#----------------------------------------------------------------------------
#          I N T E R A C T I O N   W I T H   T H E   U S E R
#----------------------------------------------------------------------------
def process_ui_action(name, flags=0):
    """
    Invokes an IDA UI action by name

    @param name: Command name
    @param flags: Reserved. Must be zero
    @return: Boolean
    """
    return ida_kernwin.process_ui_action(name, flags)

ask_seg = ida_kernwin.ask_seg
ask_yn = ida_kernwin.ask_yn
msg = ida_kernwin.msg
warning = ida_kernwin.warning
error = ida_kernwin.error
set_ida_state = ida_auto.set_ida_state


IDA_STATUS_READY    = 0 # READY     IDA is idle
IDA_STATUS_THINKING = 1 # THINKING  Analyzing but the user may press keys
IDA_STATUS_WAITING  = 2 # WAITING   Waiting for the user input
IDA_STATUS_WORK     = 3 # BUSY      IDA is busy


refresh_idaview_anyway = ida_kernwin.refresh_idaview_anyway
refresh_lists = ida_kernwin.refresh_choosers


#----------------------------------------------------------------------------
#                        S E G M E N T A T I O N
#----------------------------------------------------------------------------
def sel2para(sel):
    """
    Get a selector value

    @param sel: the selector number

    @return: selector value if found
             otherwise the input value (sel)

    @note: selector values are always in paragraphs
    """
    s = ida_pro.sel_pointer()
    base = ida_pro.ea_pointer()
    res,tmp = ida_segment.getn_selector(sel, s.cast(), base.cast())

    if not res:
        return sel
    else:
        return base.value()


def find_selector(val):
    """
    Find a selector which has the specifed value

    @param val: value to search for

    @return: the selector number if found,
             otherwise the input value (val & 0xFFFF)

    @note: selector values are always in paragraphs
    """
    return ida_segment.find_selector(val) & 0xFFFF


set_selector = ida_segment.set_selector
del_selector = ida_segment.del_selector


def get_first_seg():
    """
    Get first segment

    @return: address of the start of the first segment
        BADADDR - no segments are defined
    """
    seg = ida_segment.get_first_seg()
    if not seg:
        return BADADDR
    else:
        return seg.start_ea


def get_next_seg(ea):
    """
    Get next segment

    @param ea: linear address

    @return: start of the next segment
             BADADDR - no next segment
    """
    nextseg = ida_segment.get_next_seg(ea)
    if not nextseg:
        return BADADDR
    else:
        return nextseg.start_ea


def get_segm_start(ea):
    """
    Get start address of a segment

    @param ea: any address in the segment

    @return: start of segment
             BADADDR - the specified address doesn't belong to any segment
    """
    seg = ida_segment.getseg(ea)

    if not seg:
        return BADADDR
    else:
        return seg.start_ea


def get_segm_end(ea):
    """
    Get end address of a segment

    @param ea: any address in the segment

    @return: end of segment (an address past end of the segment)
             BADADDR - the specified address doesn't belong to any segment
    """
    seg = ida_segment.getseg(ea)

    if not seg:
        return BADADDR
    else:
        return seg.end_ea


def get_segm_name(ea):
    """
    Get name of a segment

    @param ea: any address in the segment

    @return: "" - no segment at the specified address
    """
    seg = ida_segment.getseg(ea)

    if not seg:
        return ""
    else:
        name = ida_segment.get_segm_name(seg)

        if not name:
            return ""
        else:
            return name


def add_segm_ex(startea, endea, base, use32, align, comb, flags):
    """
    Create a new segment

    @param startea: linear address of the start of the segment
    @param endea: linear address of the end of the segment
               this address will not belong to the segment
               'endea' should be higher than 'startea'
    @param base: base paragraph or selector of the segment.
               a paragraph is 16byte memory chunk.
               If a selector value is specified, the selector should be
               already defined.
    @param use32: 0: 16bit segment, 1: 32bit segment, 2: 64bit segment
    @param align: segment alignment. see below for alignment values
    @param comb: segment combination. see below for combination values.
    @param flags: combination of ADDSEG_... bits

    @return: 0-failed, 1-ok
    """
    s = ida_segment.segment_t()
    s.start_ea = startea
    s.end_ea   = endea
    s.sel      = ida_segment.setup_selector(base)
    s.bitness  = use32
    s.align    = align
    s.comb     = comb
    return ida_segment.add_segm_ex(s, "", "", flags)

ADDSEG_NOSREG  = ida_segment.ADDSEG_NOSREG  # set all default segment register values
                                            # to BADSELs
                                            # (undefine all default segment registers)
ADDSEG_OR_DIE  = ida_segment. ADDSEG_OR_DIE # qexit() if can't add a segment
ADDSEG_NOTRUNC = ida_segment.ADDSEG_NOTRUNC # don't truncate the new segment at the beginning
                                            # of the next segment if they overlap.
                                            # destroy/truncate old segments instead.
ADDSEG_QUIET   = ida_segment.ADDSEG_QUIET   # silent mode, no "Adding segment..." in the messages window
ADDSEG_FILLGAP = ida_segment.ADDSEG_FILLGAP # If there is a gap between the new segment
                                            # and the previous one, and this gap is less
                                            # than 64K, then fill the gap by extending the
                                            # previous segment and adding .align directive
                                            # to it. This way we avoid gaps between segments.
                                            # Too many gaps lead to a virtual array failure.
                                            # It cannot hold more than ~1000 gaps.
ADDSEG_SPARSE  = ida_segment.ADDSEG_SPARSE  # Use sparse storage method for the new segment

def AddSeg(startea, endea, base, use32, align, comb):
    return add_segm_ex(startea, endea, base, use32, align, comb, ADDSEG_NOSREG)

del_segm = ida_segment.del_segm

SEGMOD_KILL   = ida_segment.SEGMOD_KILL   # disable addresses if segment gets
                                     # shrinked or deleted
SEGMOD_KEEP   = ida_segment.SEGMOD_KEEP   # keep information (code & data, etc)
SEGMOD_SILENT = ida_segment.SEGMOD_SILENT # be silent


def set_segment_bounds(ea, startea, endea, flags):
    """
    Change segment boundaries

    @param ea: any address in the segment
    @param startea: new start address of the segment
    @param endea: new end address of the segment
    @param flags: combination of SEGMOD_... flags

    @return: boolean success
    """
    return ida_segment.set_segm_start(ea, startea, flags) & \
           ida_segment.set_segm_end(ea, endea, flags)


def set_segm_name(ea, name):
    """
    Change name of the segment

    @param ea: any address in the segment
    @param name: new name of the segment

    @return: success (boolean)
    """
    seg = ida_segment.getseg(ea)

    if not seg:
        return False

    return ida_segment.set_segm_name(seg, name)


def set_segm_class(ea, segclass):
    """
    Change class of the segment

    @param ea: any address in the segment
    @param segclass: new class of the segment

    @return: success (boolean)
    """
    seg = ida_segment.getseg(ea)

    if not seg:
        return False

    return ida_segment.set_segm_class(seg, segclass)


def set_segm_alignment(ea, alignment):
    """
    Change alignment of the segment

    @param ea: any address in the segment
    @param alignment: new alignment of the segment (one of the sa... constants)

    @return: success (boolean)
    """
    return set_segm_attr(ea, SEGATTR_ALIGN, alignment)


if ida_idaapi.uses_swig_builtins:
    _scope = ida_segment.segment_t
else:
    _scope = ida_segment
saAbs        = _scope.saAbs        # Absolute segment.
saRelByte    = _scope.saRelByte    # Relocatable, byte aligned.
saRelWord    = _scope.saRelWord    # Relocatable, word (2-byte, 16-bit) aligned.
saRelPara    = _scope.saRelPara    # Relocatable, paragraph (16-byte) aligned.
saRelPage    = _scope.saRelPage    # Relocatable, aligned on 256-byte boundary
                                   # (a "page" in the original Intel specification).
saRelDble    = _scope.saRelDble    # Relocatable, aligned on a double word
                                   # (4-byte) boundary. This value is used by
                                   # the PharLap OMF for the same alignment.
saRel4K      = _scope.saRel4K      # This value is used by the PharLap OMF for
                                   # page (4K) alignment. It is not supported
                                   # by LINK.
saGroup      = _scope.saGroup      # Segment group
saRel32Bytes = _scope.saRel32Bytes # 32 bytes
saRel64Bytes = _scope.saRel64Bytes # 64 bytes
saRelQword   = _scope.saRelQword   # 8 bytes


def set_segm_combination(segea, comb):
    """
    Change combination of the segment

    @param segea: any address in the segment
    @param comb: new combination of the segment (one of the sc... constants)

    @return: success (boolean)
    """
    return set_segm_attr(segea, SEGATTR_COMB, comb)


scPriv   = _scope.scPriv   # Private. Do not combine with any other program
                           # segment.
scPub    = _scope.scPub    # Public. Combine by appending at an offset that
                           # meets the alignment requirement.
scPub2   = _scope.scPub2   # As defined by Microsoft, same as C=2 (public).
scStack  = _scope.scStack  # Stack. Combine as for C=2. This combine type
                           # forces byte alignment.
scCommon = _scope.scCommon # Common. Combine by overlay using maximum size.
scPub3   = _scope.scPub3   # As defined by Microsoft, same as C=2 (public).


def set_segm_addressing(ea, bitness):
    """
    Change segment addressing

    @param ea: any address in the segment
    @param bitness: 0: 16bit, 1: 32bit, 2: 64bit

    @return: success (boolean)
    """
    seg = ida_segment.getseg(ea)

    if not seg:
        return False

    seg.bitness = bitness

    return True


def selector_by_name(segname):
    """
    Get segment selector by name

    @param segname: name of segment

    @return: segment selector or BADADDR
    """
    seg = ida_segment.get_segm_by_name(segname)

    if not seg:
        return BADADDR

    return seg.sel


def set_default_sreg_value(ea, reg, value):
    """
    Set default segment register value for a segment

    @param ea: any address in the segment
               if no segment is present at the specified address
               then all segments will be affected
    @param reg: name of segment register
    @param value: default value of the segment register. -1-undefined.
    """
    seg = ida_segment.getseg(ea)

    reg = ida_idp.str2reg(reg);
    if seg and reg >= 0:
        return ida_segregs.set_default_sreg_value(seg, reg, value)
    else:
        return False


def set_segm_type(segea, segtype):
    """
    Set segment type

    @param segea: any address within segment
    @param segtype: new segment type:

    @return: !=0 - ok
    """
    seg = ida_segment.getseg(segea)

    if not seg:
        return False

    seg.type = segtype
    return seg.update()


SEG_NORM   = _scope.SEG_NORM
SEG_XTRN   = _scope.SEG_XTRN   # * segment with 'extern' definitions
                               #   no instructions are allowed
SEG_CODE   = _scope.SEG_CODE   # pure code segment
SEG_DATA   = _scope.SEG_DATA   # pure data segment
SEG_IMP    = _scope.SEG_IMP    # implementation segment
SEG_GRP    = _scope.SEG_GRP    # * group of segments
                               #   no instructions are allowed
SEG_NULL   = _scope.SEG_NULL   # zero-length segment
SEG_UNDF   = _scope.SEG_UNDF   # undefined segment type
SEG_BSS    = _scope.SEG_BSS    # uninitialized segment
SEG_ABSSYM = _scope.SEG_ABSSYM # * segment with definitions of absolute symbols
                               #   no instructions are allowed
SEG_COMM   = _scope.SEG_COMM   # * segment with communal definitions
                               #   no instructions are allowed
SEG_IMEM   = _scope.SEG_IMEM   # internal processor memory & sfr (8051)


def get_segm_attr(segea, attr):
    """
    Get segment attribute

    @param segea: any address within segment
    @param attr: one of SEGATTR_... constants
    """
    seg = ida_segment.getseg(segea)
    assert seg, "could not find segment at 0x%x" % segea
    if attr in [ SEGATTR_ES, SEGATTR_CS, SEGATTR_SS, SEGATTR_DS, SEGATTR_FS, SEGATTR_GS ]:
        return ida_segment.get_defsr(seg, _SEGATTRMAP[attr][1])
    else:
        return _IDC_GetAttr(seg, _SEGATTRMAP, attr)


def set_segm_attr(segea, attr, value):
    """
    Set segment attribute

    @param segea: any address within segment
    @param attr: one of SEGATTR_... constants

    @note: Please note that not all segment attributes are modifiable.
           Also some of them should be modified using special functions
           like set_segm_addressing, etc.
    """
    seg = ida_segment.getseg(segea)
    assert seg, "could not find segment at 0x%x" % segea
    if attr in [ SEGATTR_ES, SEGATTR_CS, SEGATTR_SS, SEGATTR_DS, SEGATTR_FS, SEGATTR_GS ]:
        ida_segment.set_defsr(seg, _SEGATTRMAP[attr][1], value)
    else:
        _IDC_SetAttr(seg, _SEGATTRMAP, attr, value)
    return seg.update()


SEGATTR_START   =  0      # starting address
SEGATTR_END     =  4      # ending address
SEGATTR_ORGBASE = 16
SEGATTR_ALIGN   = 20      # alignment
SEGATTR_COMB    = 21      # combination
SEGATTR_PERM    = 22      # permissions
SEGATTR_BITNESS = 23      # bitness (0: 16, 1: 32, 2: 64 bit segment)
                          # Note: modifying the attribute directly does
                          #       not lead to the reanalysis of the segment.
                          #       Using set_segm_addressing() is more correct.
SEGATTR_FLAGS   = 24      # segment flags
SEGATTR_SEL     = 28      # segment selector
SEGATTR_ES      = 32      # default ES value
SEGATTR_CS      = 36      # default CS value
SEGATTR_SS      = 40      # default SS value
SEGATTR_DS      = 44      # default DS value
SEGATTR_FS      = 48      # default FS value
SEGATTR_GS      = 52      # default GS value
SEGATTR_TYPE    = 96      # segment type
SEGATTR_COLOR   = 100     # segment color

# Redefining these for 64-bit
if __EA64__:
    SEGATTR_START   = 0
    SEGATTR_END     = 8
    SEGATTR_ORGBASE = 32
    SEGATTR_ALIGN   = 40
    SEGATTR_COMB    = 41
    SEGATTR_PERM    = 42
    SEGATTR_BITNESS = 43
    SEGATTR_FLAGS   = 44
    SEGATTR_SEL     = 48
    SEGATTR_ES      = 56
    SEGATTR_CS      = 64
    SEGATTR_SS      = 72
    SEGATTR_DS      = 80
    SEGATTR_FS      = 88
    SEGATTR_GS      = 96
    SEGATTR_TYPE    = 184
    SEGATTR_COLOR   = 188

_SEGATTRMAP = {
    SEGATTR_START   : (True, 'start_ea'),
    SEGATTR_END     : (True, 'end_ea'),
    SEGATTR_ORGBASE : (False, 'orgbase'),
    SEGATTR_ALIGN   : (False, 'align'),
    SEGATTR_COMB    : (False, 'comb'),
    SEGATTR_PERM    : (False, 'perm'),
    SEGATTR_BITNESS : (False, 'bitness'),
    SEGATTR_FLAGS   : (False, 'flags'),
    SEGATTR_SEL     : (False, 'sel'),
    SEGATTR_ES      : (False, 0),
    SEGATTR_CS      : (False, 1),
    SEGATTR_SS      : (False, 2),
    SEGATTR_DS      : (False, 3),
    SEGATTR_FS      : (False, 4),
    SEGATTR_GS      : (False, 5),
    SEGATTR_TYPE    : (False, 'type'),
    SEGATTR_COLOR   : (False, 'color'),
}

# Valid segment flags
SFL_COMORG   = 0x01       # IDP dependent field (IBM PC: if set, ORG directive is not commented out)
SFL_OBOK     = 0x02       # orgbase is present? (IDP dependent field)
SFL_HIDDEN   = 0x04       # is the segment hidden?
SFL_DEBUG    = 0x08       # is the segment created for the debugger?
SFL_LOADER   = 0x10       # is the segment created by the loader?
SFL_HIDETYPE = 0x20       # hide segment type (do not print it in the listing)


def move_segm(ea, to, flags):
    """
    Move a segment to a new address
    This function moves all information to the new address
    It fixes up address sensitive information in the kernel
    The total effect is equal to reloading the segment to the target address

    @param ea: any address within the segment to move
    @param to: new segment start address
    @param flags: combination MFS_... constants

    @returns: MOVE_SEGM_... error code
    """
    seg = ida_segment.getseg(ea)
    if not seg:
        return MOVE_SEGM_PARAM
    return ida_segment.move_segm(seg, to, flags)


MSF_SILENT    = 0x0001    # don't display a "please wait" box on the screen
MSF_NOFIX     = 0x0002    # don't call the loader to fix relocations
MSF_LDKEEP    = 0x0004    # keep the loader in the memory (optimization)
MSF_FIXONCE   = 0x0008    # valid for rebase_program(): call loader only once

MOVE_SEGM_OK          =  0     # all ok
MOVE_SEGM_PARAM       = -1     # The specified segment does not exist
MOVE_SEGM_ROOM        = -2     # Not enough free room at the target address
MOVE_SEGM_IDP         = -3     # IDP module forbids moving the segment
MOVE_SEGM_CHUNK       = -4     # Too many chunks are defined, can't move
MOVE_SEGM_LOADER      = -5     # The segment has been moved but the loader complained
MOVE_SEGM_ODD         = -6     # Can't move segments by an odd number of bytes
MOVE_SEGM_ORPHAN      = -7,    # Orphan bytes hinder segment movement
MOVE_SEGM_DEBUG       = -8,    # Debugger segments cannot be moved
MOVE_SEGM_SOURCEFILES = -9,    # Source files ranges of addresses hinder segment movement
MOVE_SEGM_MAPPING     = -10,   # Memory mapping ranges of addresses hinder segment movement
MOVE_SEGM_INVAL       = -11,   # Invalid argument (delta/target does not fit the address space)


rebase_program = ida_segment.rebase_program
set_storage_type = ida_bytes.change_storage_type


STT_VA = 0  # regular storage: virtual arrays, an explicit flag for each byte
STT_MM = 1  # memory map: sparse storage. useful for huge objects


#----------------------------------------------------------------------------
#                    C R O S S   R E F E R E N C E S
#----------------------------------------------------------------------------
#      Flow types (combine with XREF_USER!):
fl_CF   = 16              # Call Far
fl_CN   = 17              # Call Near
fl_JF   = 18              # jumpto Far
fl_JN   = 19              # jumpto Near
fl_F    = 21              # Ordinary flow

XREF_USER = 32            # All user-specified xref types
                          # must be combined with this bit


# Mark exec flow 'from' 'to'
add_cref = ida_xref.add_cref
del_cref = ida_xref.del_cref


# The following functions include the ordinary flows:
# (the ordinary flow references are returned first)
get_first_cref_from = ida_xref.get_first_cref_from
get_next_cref_from = ida_xref.get_next_cref_from
get_first_cref_to = ida_xref.get_first_cref_to
get_next_cref_to = ida_xref.get_next_cref_to


# The following functions don't take into account the ordinary flows:
get_first_fcref_from = ida_xref.get_first_fcref_from
get_next_fcref_from = ida_xref.get_next_fcref_from
get_first_fcref_to = ida_xref.get_first_fcref_to
get_next_fcref_to = ida_xref.get_next_fcref_to


# Data reference types (combine with XREF_USER!):
dr_O    = ida_xref.dr_O  # Offset
dr_W    = ida_xref.dr_W  # Write
dr_R    = ida_xref.dr_R  # Read
dr_T    = ida_xref.dr_T  # Text (names in manual operands)
dr_I    = ida_xref.dr_I  # Informational

add_dref = ida_xref.add_dref
del_dref = ida_xref.del_dref
get_first_dref_from = ida_xref.get_first_dref_from
get_next_dref_from = ida_xref.get_next_dref_from
get_first_dref_to = ida_xref.get_first_dref_to
get_next_dref_to = ida_xref.get_next_dref_to


def get_xref_type():
    """
    Return type of the last xref obtained by
    [RD]first/next[B0] functions.

    @return: constants fl_* or dr_*
    """
    raise DeprecatedIDCError("use XrefsFrom() XrefsTo() from idautils instead.")


#----------------------------------------------------------------------------
#                            F I L E   I / O
#----------------------------------------------------------------------------
def fopen(f, mode):
    raise DeprecatedIDCError("fopen() deprecated. Use Python file objects instead.")

def fclose(handle):
    raise DeprecatedIDCError("fclose() deprecated. Use Python file objects instead.")

def filelength(handle):
    raise DeprecatedIDCError("filelength() deprecated. Use Python file objects instead.")

def fseek(handle, offset, origin):
    raise DeprecatedIDCError("fseek() deprecated. Use Python file objects instead.")

def ftell(handle):
    raise DeprecatedIDCError("ftell() deprecated. Use Python file objects instead.")


def LoadFile(filepath, pos, ea, size):
    """
    Load file into IDA database

    @param filepath: path to input file
    @param pos: position in the file
    @param ea: linear address to load
    @param size: number of bytes to load

    @return: 0 - error, 1 - ok
    """
    li = ida_diskio.open_linput(filepath, False)

    if li:
        retval = ida_loader.file2base(li, pos, ea, ea+size, False)
        ida_diskio.close_linput(li)
        return retval
    else:
        return 0

def loadfile(filepath, pos, ea, size): return LoadFile(filepath, pos, ea, size)


def SaveFile(filepath, pos, ea, size):
    """
    Save from IDA database to file

    @param filepath: path to output file
    @param pos: position in the file
    @param ea: linear address to save from
    @param size: number of bytes to save

    @return: 0 - error, 1 - ok
    """
    if ( os.path.isfile(filepath) ):
        of = ida_diskio.fopenM(filepath)
    else:
        of = ida_diskio.fopenWB(filepath)


    if of:
        retval = ida_loader.base2file(of, pos, ea, ea+size)
        ida_diskio.eclose(of)
        return retval
    else:
        return 0

def savefile(filepath, pos, ea, size): return SaveFile(filepath, pos, ea, size)


def fgetc(handle):
    raise DeprecatedIDCError("fgetc() deprecated. Use Python file objects instead.")

def fputc(byte, handle):
    raise DeprecatedIDCError("fputc() deprecated. Use Python file objects instead.")

def fprintf(handle, format, *args):
    raise DeprecatedIDCError("fprintf() deprecated. Use Python file objects instead.")

def readshort(handle, mostfirst):
    raise DeprecatedIDCError("readshort() deprecated. Use Python file objects instead.")

def readlong(handle, mostfirst):
    raise DeprecatedIDCError("readlong() deprecated. Use Python file objects instead.")

def writeshort(handle, word, mostfirst):
    raise DeprecatedIDCError("writeshort() deprecated. Use Python file objects instead.")

def writelong(handle, dword, mostfirst):
    raise DeprecatedIDCError("writelong() deprecated. Use Python file objects instead.")

def readstr(handle):
    raise DeprecatedIDCError("readstr() deprecated. Use Python file objects instead.")

def writestr(handle, s):
    raise DeprecatedIDCError("writestr() deprecated. Use Python file objects instead.")

# ----------------------------------------------------------------------------
#                           F U N C T I O N S
# ----------------------------------------------------------------------------

add_func = ida_funcs.add_func
del_func = ida_funcs.del_func
set_func_end = ida_funcs.set_func_end


def get_next_func(ea):
    """
    Find next function

    @param ea: any address belonging to the function

    @return:        BADADDR - no more functions
            otherwise returns the next function start address
    """
    func = ida_funcs.get_next_func(ea)

    if not func:
        return BADADDR
    else:
        return func.start_ea


def get_prev_func(ea):
    """
    Find previous function

    @param ea: any address belonging to the function

    @return: BADADDR - no more functions
            otherwise returns the previous function start address
    """
    func = ida_funcs.get_prev_func(ea)

    if not func:
        return BADADDR
    else:
        return func.start_ea


def get_func_attr(ea, attr):
    """
    Get a function attribute

    @param ea: any address belonging to the function
    @param attr: one of FUNCATTR_... constants

    @return: BADADDR - error otherwise returns the attribute value
    """
    func = ida_funcs.get_func(ea)

    return _IDC_GetAttr(func, _FUNCATTRMAP, attr) if func else BADADDR


def set_func_attr(ea, attr, value):
    """
    Set a function attribute

    @param ea: any address belonging to the function
    @param attr: one of FUNCATTR_... constants
    @param value: new value of the attribute

    @return: 1-ok, 0-failed
    """
    func = ida_funcs.get_func(ea)

    if func:
        _IDC_SetAttr(func, _FUNCATTRMAP, attr, value)
        return ida_funcs.update_func(func)
    return 0


FUNCATTR_START   =  0     # readonly: function start address
FUNCATTR_END     =  4     # readonly: function end address
FUNCATTR_FLAGS   =  8     # function flags
FUNCATTR_FRAME   = 16     # readonly: function frame id
FUNCATTR_FRSIZE  = 20     # readonly: size of local variables
FUNCATTR_FRREGS  = 24     # readonly: size of saved registers area
FUNCATTR_ARGSIZE = 28     # readonly: number of bytes purged from the stack
FUNCATTR_FPD     = 32     # frame pointer delta
FUNCATTR_COLOR   = 36     # function color code
FUNCATTR_OWNER   = 16     # readonly: chunk owner (valid only for tail chunks)
FUNCATTR_REFQTY  = 20     # readonly: number of chunk parents (valid only for tail chunks)

# Redefining the constants for ea64
if __EA64__:
    FUNCATTR_START   =  0
    FUNCATTR_END     =  8
    FUNCATTR_FLAGS   = 16
    FUNCATTR_FRAME   = 24
    FUNCATTR_FRSIZE  = 32
    FUNCATTR_FRREGS  = 40
    FUNCATTR_ARGSIZE = 48
    FUNCATTR_FPD     = 56
    FUNCATTR_COLOR   = 64
    FUNCATTR_OWNER   = 24
    FUNCATTR_REFQTY  = 32

_FUNCATTRMAP = {
    FUNCATTR_START   : (True, 'start_ea'),
    FUNCATTR_END     : (True, 'end_ea'),
    FUNCATTR_FLAGS   : (False, 'flags'),
    FUNCATTR_FRAME   : (True, 'frame'),
    FUNCATTR_FRSIZE  : (True, 'frsize'),
    FUNCATTR_FRREGS  : (True, 'frregs'),
    FUNCATTR_ARGSIZE : (True, 'argsize'),
    FUNCATTR_FPD     : (False, 'fpd'),
    FUNCATTR_COLOR   : (False, 'color'),
    FUNCATTR_OWNER   : (True, 'owner'),
    FUNCATTR_REFQTY  : (True, 'refqty')
}


def get_func_flags(ea):
    """
    Retrieve function flags

    @param ea: any address belonging to the function

    @return: -1 - function doesn't exist otherwise returns the flags
    """
    func = ida_funcs.get_func(ea)

    if not func:
        return -1
    else:
        return func.flags


if ida_idaapi.uses_swig_builtins:
    _scope = ida_funcs.func_t
else:
    _scope = ida_funcs

FUNC_NORET         = _scope.FUNC_NORET         # function doesn't return
FUNC_FAR           = _scope.FUNC_FAR           # far function
FUNC_LIB           = _scope.FUNC_LIB           # library function
FUNC_STATIC        = _scope.FUNC_STATICDEF     # static function
FUNC_FRAME         = _scope.FUNC_FRAME         # function uses frame pointer (BP)
FUNC_USERFAR       = _scope.FUNC_USERFAR       # user has specified far-ness
                                               # of the function
FUNC_HIDDEN        = _scope.FUNC_HIDDEN        # a hidden function
FUNC_THUNK         = _scope.FUNC_THUNK         # thunk (jump) function
FUNC_BOTTOMBP      = _scope.FUNC_BOTTOMBP      # BP points to the bottom of the stack frame
FUNC_NORET_PENDING = _scope.FUNC_NORET_PENDING # Function 'non-return' analysis
                                               # must be performed. This flag is
                                               # verified upon func_does_return()
FUNC_SP_READY      = _scope.FUNC_SP_READY      # SP-analysis has been performed
                                               # If this flag is on, the stack
                                               # change points should not be not
                                               # modified anymore. Currently this
                                               # analysis is performed only for PC
FUNC_PURGED_OK     = _scope.FUNC_PURGED_OK     # 'argsize' field has been validated.
                                               # If this bit is clear and 'argsize'
                                               # is 0, then we do not known the real
                                               # number of bytes removed from
                                               # the stack. This bit is handled
                                               # by the processor module.
FUNC_TAIL          = _scope.FUNC_TAIL          # This is a function tail.
                                               # Other bits must be clear
                                               # (except FUNC_HIDDEN)
FUNC_LUMINA        = _scope.FUNC_LUMINA        # Function info is provided by Lumina.
FUNC_OUTLINE       = _scope.FUNC_OUTLINE       # Outlined code, not a real function.


def set_func_flags(ea, flags):
    """
    Change function flags

    @param ea: any address belonging to the function
    @param flags: see get_func_flags() for explanations

    @return: !=0 - ok
    """
    func = ida_funcs.get_func(ea)

    if not func:
        return 0
    else:
        func.flags = flags
        ida_funcs.update_func(func)
        return 1


def get_func_name(ea):
    """
    Retrieve function name

    @param ea: any address belonging to the function

    @return: null string - function doesn't exist
            otherwise returns function name
    """
    name = ida_funcs.get_func_name(ea)

    if not name:
        return ""
    else:
        return name


def get_func_cmt(ea, repeatable):
    """
    Retrieve function comment

    @param ea: any address belonging to the function
    @param repeatable: 1: get repeatable comment
            0: get regular comment

    @return: function comment string
    """
    func = ida_funcs.get_func(ea)

    if not func:
        return ""
    else:
        comment = ida_funcs.get_func_cmt(func, repeatable)

        if not comment:
            return ""
        else:
            return comment


def set_func_cmt(ea, cmt, repeatable):
    """
    Set function comment

    @param ea: any address belonging to the function
    @param cmt: a function comment line
    @param repeatable: 1: get repeatable comment
            0: get regular comment
    """
    func = ida_funcs.get_func(ea)

    if not func:
        return None
    else:
        return ida_funcs.set_func_cmt(func, cmt, repeatable)


def choose_func(title):
    """
    Ask the user to select a function

    Arguments:

    @param title: title of the dialog box

    @return: -1 - user refused to select a function
             otherwise returns the selected function start address
    """
    f = ida_kernwin.choose_func(title, ida_idaapi.BADADDR)
    return BADADDR if f is None else f.start_ea


def get_func_off_str(ea):
    """
    Convert address to 'funcname+offset' string

    @param ea: address to convert

    @return: if the address belongs to a function then return a string
             formed as 'name+offset' where 'name' is a function name
             'offset' is offset within the function else return null string
    """

    flags = ida_name.GNCN_NOCOLOR | ida_name.GNCN_REQFUNC
    return ida_name.get_nice_colored_name(ea, flags)


def find_func_end(ea):
    """
    Determine a new function boundaries

    @param ea: starting address of a new function

    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    func = ida_funcs.func_t(ea)

    res = ida_funcs.find_func_bounds(func, ida_funcs.FIND_FUNC_DEFINE)

    if res == ida_funcs.FIND_FUNC_UNDEF:
        return BADADDR
    else:
        return func.end_ea


def get_frame_id(ea):
    """
    Get ID of function frame structure

    @param ea: any address belonging to the function

    @return: ID of function frame or None In order to access stack variables
             you need to use structure member manipulaion functions with the
             obtained ID.
    """
    frame = ida_frame.get_frame(ea)

    if frame:
        return frame.id
    else:
        return None


def get_frame_lvar_size(ea):
    """
    Get size of local variables in function frame

    @param ea: any address belonging to the function

    @return: Size of local variables in bytes.
             If the function doesn't have a frame, return 0
             If the function does't exist, return None
    """
    return get_func_attr(ea, FUNCATTR_FRSIZE)


def get_frame_regs_size(ea):
    """
    Get size of saved registers in function frame

    @param ea: any address belonging to the function

    @return: Size of saved registers in bytes.
             If the function doesn't have a frame, return 0
             This value is used as offset for BP (if FUNC_FRAME is set)
             If the function does't exist, return None
    """
    return get_func_attr(ea, FUNCATTR_FRREGS)


def get_frame_args_size(ea):
    """
    Get size of arguments in function frame which are purged upon return

    @param ea: any address belonging to the function

    @return: Size of function arguments in bytes.
             If the function doesn't have a frame, return 0
             If the function does't exist, return -1
    """
    return get_func_attr(ea, FUNCATTR_ARGSIZE)


def get_frame_size(ea):
    """
    Get full size of function frame

    @param ea: any address belonging to the function
    @returns: Size of function frame in bytes.
                This function takes into account size of local
                variables + size of saved registers + size of
                return address + size of function arguments
                If the function doesn't have a frame, return size of
                function return address in the stack.
                If the function does't exist, return 0
    """
    func = ida_funcs.get_func(ea)

    if not func:
        return 0
    else:
        return ida_frame.get_frame_size(func)


def set_frame_size(ea, lvsize, frregs, argsize):
    """
    Make function frame

    @param ea: any address belonging to the function
    @param lvsize: size of function local variables
    @param frregs: size of saved registers
    @param argsize: size of function arguments

    @return: ID of function frame or -1
             If the function did not have a frame, the frame
             will be created. Otherwise the frame will be modified
    """
    func = ida_funcs.get_func(ea)
    if func is None:
        return -1

    frameid = ida_frame.add_frame(func, lvsize, frregs, argsize)

    if not frameid:
        if not ida_frame.set_frame_size(func, lvsize, frregs, argsize):
            return -1

    return func.frame


def get_spd(ea):
    """
    Get current delta for the stack pointer

    @param ea: end address of the instruction
               i.e.the last address of the instruction+1

    @return: The difference between the original SP upon
             entering the function and SP for the specified address
    """
    func = ida_funcs.get_func(ea)

    if not func:
        return None

    return ida_frame.get_spd(func, ea)


def get_sp_delta(ea):
    """
    Get modification of SP made by the instruction

    @param ea: end address of the instruction
               i.e.the last address of the instruction+1

    @return: Get modification of SP made at the specified location
             If the specified location doesn't contain a SP change point, return 0
             Otherwise return delta of SP modification
    """
    func = ida_funcs.get_func(ea)

    if not func:
        return None

    return ida_frame.get_sp_delta(func, ea)


# ----------------------------------------------------------------------------
#                              S T A C K
# ----------------------------------------------------------------------------

def add_auto_stkpnt(func_ea, ea, delta):
    """
    Add automatical SP register change point
    @param func_ea: function start
    @param ea: linear address where SP changes
               usually this is the end of the instruction which
               modifies the stack pointer (insn.ea+insn.size)
    @param delta: difference between old and new values of SP
    @return: 1-ok, 0-failed
    """
    pfn = ida_funcs.get_func(func_ea)
    if not pfn:
        return 0
    return ida_frame.add_auto_stkpnt(pfn, ea, delta)

add_user_stkpnt = ida_frame.add_user_stkpnt

def del_stkpnt(func_ea, ea):
    """
    Delete SP register change point

    @param func_ea: function start
    @param ea: linear address
    @return: 1-ok, 0-failed
    """
    pfn = ida_funcs.get_func(func_ea)
    if not pfn:
        return 0
    return ida_frame.del_stkpnt(pfn, ea)

def get_min_spd_ea(func_ea):
    """
    Return the address with the minimal spd (stack pointer delta)
    If there are no SP change points, then return BADADDR.

    @param func_ea: function start
    @return: BADDADDR - no such function
    """
    pfn = ida_funcs.get_func(func_ea)
    if not pfn:
        return BADADDR
    return ida_frame.get_min_spd_ea(pfn)

recalc_spd = ida_frame.recalc_spd





# ----------------------------------------------------------------------------
#                        E N T R Y   P O I N T S
# ----------------------------------------------------------------------------
get_entry_qty = ida_entry.get_entry_qty
add_entry = ida_entry.add_entry
get_entry_ordinal = ida_entry.get_entry_ordinal
get_entry = ida_entry.get_entry
get_entry_name = ida_entry.get_entry_name
rename_entry = ida_entry.rename_entry


# ----------------------------------------------------------------------------
#                              F I X U P S
# ----------------------------------------------------------------------------
get_next_fixup_ea = ida_fixup.get_next_fixup_ea
get_prev_fixup_ea = ida_fixup.get_prev_fixup_ea


def get_fixup_target_type(ea):
    """
    Get fixup target type

    @param ea: address to get information about

    @return: 0 - no fixup at the specified address
                 otherwise returns fixup type
    """
    fd = ida_fixup.fixup_data_t()

    if not fd.get(ea):
        return 0

    return fd.get_type()


FIXUP_OFF8      = 13      # 8-bit offset.
FIXUP_OFF16     = 1       # 16-bit offset.
FIXUP_SEG16     = 2       # 16-bit base--logical segment base (selector).
FIXUP_PTR32     = 3       # 32-bit long pointer (16-bit base:16-bit
                          # offset).
FIXUP_OFF32     = 4       # 32-bit offset.
FIXUP_PTR48     = 5       # 48-bit pointer (16-bit base:32-bit offset).
FIXUP_HI8       = 6       # high  8 bits of 16bit offset
FIXUP_HI16      = 7       # high 16 bits of 32bit offset
FIXUP_LOW8      = 8       # low   8 bits of 16bit offset
FIXUP_LOW16     = 9       # low  16 bits of 32bit offset
FIXUP_OFF64     = 12      # 64-bit offset
FIXUP_CUSTOM    = 0x8000  # fixups with this bit are processed by
                          # processor module/plugin

def get_fixup_target_flags(ea):
    """
    Get fixup target flags

    @param ea: address to get information about

    @return: 0 - no fixup at the specified address
                 otherwise returns fixup target flags
    """
    fd = ida_fixup.fixup_data_t()

    if not fd.get(ea):
        return 0

    return fd.get_flags()


FIXUPF_REL       = 0x1  # fixup is relative to the linear address
FIXUPF_EXTDEF    = 0x2  # target is a location (otherwise - segment)
FIXUPF_UNUSED    = 0x4  # fixup is ignored by IDA
FIXUPF_CREATED   = 0x8  # fixup was not present in the input file


def get_fixup_target_sel(ea):
    """
    Get fixup target selector

    @param ea: address to get information about

    @return: BADSEL - no fixup at the specified address
                      otherwise returns fixup target selector
    """
    fd = ida_fixup.fixup_data_t()

    if not fd.get(ea):
        return BADSEL

    return fd.sel


def get_fixup_target_off(ea):
    """
    Get fixup target offset

    @param ea: address to get information about

    @return: BADADDR - no fixup at the specified address
                       otherwise returns fixup target offset
    """
    fd = ida_fixup.fixup_data_t()

    if not fd.get(ea):
        return BADADDR

    return fd.off


def get_fixup_target_dis(ea):
    """
    Get fixup target displacement

    @param ea: address to get information about

    @return: 0 - no fixup at the specified address
                 otherwise returns fixup target displacement
    """
    fd = ida_fixup.fixup_data_t()

    if not fd.get(ea):
        return 0

    return fd.displacement


def set_fixup(ea, fixuptype, fixupflags, targetsel, targetoff, displ):
    """
    Set fixup information

    @param ea: address to set fixup information about
    @param fixuptype:  fixup type. see get_fixup_target_type()
                       for possible fixup types.
    @param fixupflags: fixup flags. see get_fixup_target_flags()
                       for possible fixup types.
    @param targetsel:  target selector
    @param targetoff:  target offset
    @param displ:      displacement

    @return:        none
    """
    fd = ida_fixup.fixup_data_t(fixuptype, fixupflags)
    fd.sel = targetsel
    fd.off = targetoff
    fd.displacement = displ

    fd.set(ea)


del_fixup = ida_fixup.del_fixup


#----------------------------------------------------------------------------
#                   M A R K E D   P O S I T I O N S
#----------------------------------------------------------------------------

put_bookmark = ida_idc.mark_position
get_bookmark = ida_idc.get_marked_pos
get_bookmark_desc = ida_idc.get_mark_comment


# ----------------------------------------------------------------------------
#                          S T R U C T U R E S
# ----------------------------------------------------------------------------

get_struc_qty = ida_struct.get_struc_qty
get_first_struc_idx = ida_struct.get_first_struc_idx
get_last_struc_idx = ida_struct.get_last_struc_idx
get_next_struc_idx = ida_struct.get_next_struc_idx
get_prev_struc_idx = ida_struct.get_prev_struc_idx
get_struc_idx = ida_struct.get_struc_idx
get_struc_by_idx = ida_struct.get_struc_by_idx
get_struc_id = ida_struct.get_struc_id
get_struc_name = ida_struct.get_struc_name
get_struc_cmt = ida_struct.get_struc_cmt
get_struc_size = ida_struct.get_struc_size


def get_member_qty(sid):
    """
    Get number of members of a structure

    @param sid: structure type ID

    @return: -1 if bad structure type ID is passed otherwise
             returns number of members.

    @note: Union members are, in IDA's internals, located
           at subsequent byte offsets: member 0 -> offset 0x0,
           member 1 -> offset 0x1, etc...
    """
    s = ida_struct.get_struc(sid)
    return -1 if not s else s.memqty


def get_member_id(sid, member_offset):
    """
    @param sid: structure type ID
    @param member_offset:. The offset can be
    any offset in the member. For example,
    is a member is 4 bytes long and starts
    at offset 2, then 2,3,4,5 denote
    the same structure member.

    @return: -1 if bad structure type ID is passed or there is
    no member at the specified offset.
    otherwise returns the member id.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return -1

    m = ida_struct.get_member(s, member_offset)
    if not m:
        return -1

    return m.id


def get_prev_offset(sid, offset):
    """
    Get previous offset in a structure

    @param sid: structure type ID
    @param offset: current offset

    @return: -1 if bad structure type ID is passed,
             ida_idaapi.BADADDR if no (more) offsets in the structure,
             otherwise returns previous offset in a structure.

    @note: IDA allows 'holes' between members of a
           structure. It treats these 'holes'
           as unnamed arrays of bytes.
           This function returns a member offset or a hole offset.
           It will return size of the structure if input
           'offset' is bigger than the structure size.

    @note: Union members are, in IDA's internals, located
           at subsequent byte offsets: member 0 -> offset 0x0,
           member 1 -> offset 0x1, etc...
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return -1

    return ida_struct.get_struc_prev_offset(s, offset)


def get_next_offset(sid, offset):
    """
    Get next offset in a structure

    @param sid:     structure type ID
    @param offset: current offset

    @return: -1 if bad structure type ID is passed,
             ida_idaapi.BADADDR if no (more) offsets in the structure,
             otherwise returns next offset in a structure.

    @note: IDA allows 'holes' between members of a
           structure. It treats these 'holes'
           as unnamed arrays of bytes.
           This function returns a member offset or a hole offset.
           It will return size of the structure if input
           'offset' belongs to the last member of the structure.

    @note: Union members are, in IDA's internals, located
           at subsequent byte offsets: member 0 -> offset 0x0,
           member 1 -> offset 0x1, etc...
    """
    s = ida_struct.get_struc(sid)
    return -1 if not s else ida_struct.get_struc_next_offset(s, offset)


def get_first_member(sid):
    """
    Get offset of the first member of a structure

    @param sid: structure type ID

    @return: -1 if bad structure type ID is passed,
             ida_idaapi.BADADDR if structure has no members,
             otherwise returns offset of the first member.

    @note: IDA allows 'holes' between members of a
           structure. It treats these 'holes'
           as unnamed arrays of bytes.

    @note: Union members are, in IDA's internals, located
           at subsequent byte offsets: member 0 -> offset 0x0,
           member 1 -> offset 0x1, etc...
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return -1

    return ida_struct.get_struc_first_offset(s)


def get_last_member(sid):
    """
    Get offset of the last member of a structure

    @param sid: structure type ID

    @return: -1 if bad structure type ID is passed,
             ida_idaapi.BADADDR if structure has no members,
             otherwise returns offset of the last member.

    @note: IDA allows 'holes' between members of a
          structure. It treats these 'holes'
          as unnamed arrays of bytes.

    @note: Union members are, in IDA's internals, located
           at subsequent byte offsets: member 0 -> offset 0x0,
           member 1 -> offset 0x1, etc...
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return -1

    return ida_struct.get_struc_last_offset(s)


def get_member_offset(sid, member_name):
    """
    Get offset of a member of a structure by the member name

    @param sid: structure type ID
    @param member_name: name of structure member

    @return: -1 if bad structure type ID is passed
             or no such member in the structure
             otherwise returns offset of the specified member.

    @note: Union members are, in IDA's internals, located
           at subsequent byte offsets: member 0 -> offset 0x0,
           member 1 -> offset 0x1, etc...
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return -1

    m = ida_struct.get_member_by_name(s, member_name)
    if not m:
        return -1

    return m.get_soff()


def get_member_name(sid, member_offset):
    """
    Get name of a member of a structure

    @param sid: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.

    @return: None if bad structure type ID is passed
             or no such member in the structure
             otherwise returns name of the specified member.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return None

    m = ida_struct.get_member(s, member_offset)
    if not m:
        return None

    return ida_struct.get_member_name(m.id)


def get_member_cmt(sid, member_offset, repeatable):
    """
    Get comment of a member

    @param sid: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.
    @param repeatable: 1: get repeatable comment
                       0: get regular comment

    @return: None if bad structure type ID is passed
             or no such member in the structure
             otherwise returns comment of the specified member.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return None

    m = ida_struct.get_member(s, member_offset)
    if not m:
        return None

    return ida_struct.get_member_cmt(m.id, repeatable)


def get_member_size(sid, member_offset):
    """
    Get size of a member

    @param sid: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.

    @return: None if bad structure type ID is passed,
             or no such member in the structure
             otherwise returns size of the specified
             member in bytes.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return None

    m = ida_struct.get_member(s, member_offset)
    if not m:
        return None

    return ida_struct.get_member_size(m)


def get_member_flag(sid, member_offset):
    """
    Get type of a member

    @param sid: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.

    @return: -1 if bad structure type ID is passed
             or no such member in the structure
             otherwise returns type of the member, see bit
             definitions above. If the member type is a structure
             then function GetMemberStrid() should be used to
             get the structure type id.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return -1

    m = ida_struct.get_member(s, member_offset)
    return -1 if not m else m.flag


def get_member_strid(sid, member_offset):
    """
    Get structure id of a member

    @param sid: structure type ID
    @param member_offset: member offset. The offset can be
                          any offset in the member. For example,
                          is a member is 4 bytes long and starts
                          at offset 2, then 2,3,4,5 denote
                          the same structure member.
    @return: -1 if bad structure type ID is passed
             or no such member in the structure
             otherwise returns structure id of the member.
             If the current member is not a structure, returns -1.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return -1

    m = ida_struct.get_member(s, member_offset)
    if not m:
        return -1

    cs = ida_struct.get_sptr(m)
    if cs:
        return cs.id
    else:
        return -1


def is_union(sid):
    """
    Is a structure a union?

    @param sid: structure type ID

    @return: 1: yes, this is a union id
             0: no

    @note: Unions are a special kind of structures
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return 0

    return s.is_union()


def add_struc(index, name, is_union):
    """
    Define a new structure type

    @param index: index of new structure type
                  If another structure has the specified index,
                  then index of that structure and all other
                  structures will be incremented, freeing the specifed
                  index. If index is == -1, then the biggest index
                  number will be used.
                  See get_first_struc_idx() for the explanation of
                  structure indices and IDs.
    @param name: name of the new structure type.
    @param is_union: 0: structure
                     1: union

    @return: -1 if can't define structure type because of
             bad structure name: the name is ill-formed or is
             already used in the program.
             otherwise returns ID of the new structure type
    """
    if index == -1:
        index = BADADDR

    return ida_struct.add_struc(index, name, is_union)


def del_struc(sid):
    """
    Delete a structure type

    @param sid: structure type ID

    @return: 0 if bad structure type ID is passed
             1 otherwise the structure type is deleted. All data
             and other structure types referencing to the
             deleted structure type will be displayed as array
             of bytes.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return 0

    return ida_struct.del_struc(s)


def set_struc_idx(sid, index):
    """
    Change structure index

    @param sid: structure type ID
    @param index: new index of the structure

    @return: != 0 - ok

    @note: See get_first_struc_idx() for the explanation of
           structure indices and IDs.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return 0

    return ida_struct.set_struc_idx(s, index)


set_struc_name = ida_struct.set_struc_name
set_struc_cmt = ida_struct.set_struc_cmt


def add_struc_member(sid, name, offset, flag, typeid, nbytes, target=-1, tdelta=0, reftype=REF_OFF32):
    """
    Add structure member

    @param sid: structure type ID
    @param name: name of the new member
    @param offset: offset of the new member
                   -1 means to add at the end of the structure
    @param flag: type of the new member. Should be one of
                 FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
    @param typeid: if is_struct(flag) then typeid specifies the structure id for the member
                   if is_off0(flag) then typeid specifies the offset base.
                   if is_strlit(flag) then typeid specifies the string type (STRTYPE_...).
                   if is_stroff(flag) then typeid specifies the structure id
                   if is_enum(flag) then typeid specifies the enum id
                   if is_custom(flags) then typeid specifies the dtid and fid: dtid|(fid<<16)
                   Otherwise typeid should be -1.
    @param nbytes: number of bytes in the new member

    @param target: target address of the offset expr. You may specify it as
                   -1, ida will calculate it itself
    @param tdelta: offset target delta. usually 0
    @param reftype: see REF_... definitions

    @note: The remaining arguments are allowed only if is_off0(flag) and you want
           to specify a complex offset expression

    @return: 0 - ok, otherwise error code (one of STRUC_ERROR_*)

    """
    if is_off0(flag):
        return eval_idc('add_struc_member(%d, "%s", %d, %d, %d, %d, %d, %d, %d);' % (sid, ida_kernwin.str2user(name or ""), offset, flag, typeid, nbytes,
                                                                               target, tdelta, reftype))
    else:
        return eval_idc('add_struc_member(%d, "%s", %d, %d, %d, %d);' % (sid, ida_kernwin.str2user(name or ""), offset, flag, typeid, nbytes))


STRUC_ERROR_MEMBER_NAME    = -1 # already has member with this name (bad name)
STRUC_ERROR_MEMBER_OFFSET  = -2 # already has member at this offset
STRUC_ERROR_MEMBER_SIZE    = -3 # bad number of bytes or bad sizeof(type)
STRUC_ERROR_MEMBER_TINFO   = -4 # bad typeid parameter
STRUC_ERROR_MEMBER_STRUCT  = -5 # bad struct id (the 1st argument)
STRUC_ERROR_MEMBER_UNIVAR  = -6 # unions can't have variable sized members
STRUC_ERROR_MEMBER_VARLAST = -7 # variable sized member should be the last member in the structure


def del_struc_member(sid, member_offset):
    """
    Delete structure member

    @param sid: structure type ID
    @param member_offset: offset of the member

    @return: != 0 - ok.

    @note: IDA allows 'holes' between members of a
           structure. It treats these 'holes'
           as unnamed arrays of bytes.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return 0

    return ida_struct.del_struc_member(s, member_offset)


def set_member_name(sid, member_offset, name):
    """
    Change structure member name

    @param sid: structure type ID
    @param member_offset: offset of the member
    @param name: new name of the member

    @return: != 0 - ok.
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return 0

    return ida_struct.set_member_name(s, member_offset, name)


def set_member_type(sid, member_offset, flag, typeid, nitems, target=-1, tdelta=0, reftype=REF_OFF32):
    """
    Change structure member type

    @param sid: structure type ID
    @param member_offset: offset of the member
    @param flag: new type of the member. Should be one of
                 FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
    @param typeid: if is_struct(flag) then typeid specifies the structure id for the member
                   if is_off0(flag) then typeid specifies the offset base.
                   if is_strlit(flag) then typeid specifies the string type (STRTYPE_...).
                   if is_stroff(flag) then typeid specifies the structure id
                   if is_enum(flag) then typeid specifies the enum id
                   if is_custom(flags) then typeid specifies the dtid and fid: dtid|(fid<<16)
                   Otherwise typeid should be -1.
    @param nitems: number of items in the member

    @param target: target address of the offset expr. You may specify it as
                   -1, ida will calculate it itself
    @param tdelta: offset target delta. usually 0
    @param reftype: see REF_... definitions

    @note: The remaining arguments are allowed only if is_off0(flag) and you want
           to specify a complex offset expression

    @return: !=0 - ok.
    """
    if is_off0(flag):
        return eval_idc('set_member_type(%d, %d, %d, %d, %d, %d, %d, %d);' % (sid, member_offset, flag, typeid, nitems,
                                                                              target, tdelta, reftype))
    else:
        return eval_idc('set_member_type(%d, %d, %d, %d, %d);' % (sid, member_offset, flag, typeid, nitems))


def set_member_cmt(sid, member_offset, comment, repeatable):
    """
    Change structure member comment

    @param sid: structure type ID
    @param member_offset: offset of the member
    @param comment: new comment of the structure member
    @param repeatable: 1: change repeatable comment
                       0: change regular comment

    @return: != 0 - ok
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return 0

    m = ida_struct.get_member(s, member_offset)
    if not m:
        return 0

    return ida_struct.set_member_cmt(m, comment, repeatable)


def expand_struc(sid, offset, delta, recalc):
    """
    Expand or shrink a structure type
    @param id: structure type ID
    @param offset: offset in the structure
    @param delta: how many bytes to add or remove
    @param recalc: recalculate the locations where the structure
                               type is used
    @return: != 0 - ok
    """
    s = ida_struct.get_struc(sid)
    if not s:
        return 0

    return ida_struct.expand_struc(s, offset, delta, recalc)


def get_fchunk_attr(ea, attr):
    """
    Get a function chunk attribute

    @param ea: any address in the chunk
    @param attr: one of: FUNCATTR_START, FUNCATTR_END, FUNCATTR_OWNER, FUNCATTR_REFQTY

    @return: desired attribute or -1
    """
    func = ida_funcs.get_fchunk(ea)
    return _IDC_GetAttr(func, _FUNCATTRMAP, attr) if func else BADADDR


def set_fchunk_attr(ea, attr, value):
    """
    Set a function chunk attribute

    @param ea: any address in the chunk
    @param attr: only FUNCATTR_START, FUNCATTR_END, FUNCATTR_OWNER
    @param value: desired value

    @return: 0 if failed, 1 if success
    """
    if attr in [ FUNCATTR_START, FUNCATTR_END, FUNCATTR_OWNER ]:
        chunk = ida_funcs.get_fchunk(ea)
        if chunk:
            _IDC_SetAttr(chunk, _FUNCATTRMAP, attr, value)
            return ida_funcs.update_func(chunk)
    return 0


get_fchunk_referer = ida_funcs.get_fchunk_referer


def get_next_fchunk(ea):
    """
    Get next function chunk

    @param ea: any address

    @return:  the starting address of the next function chunk or BADADDR

    @note: This function enumerates all chunks of all functions in the database
    """
    func = ida_funcs.get_next_fchunk(ea)

    if func:
        return func.start_ea
    else:
        return BADADDR


def get_prev_fchunk(ea):
    """
    Get previous function chunk

    @param ea: any address

    @return: the starting address of the function chunk or BADADDR

    @note: This function enumerates all chunks of all functions in the database
    """
    func = ida_funcs.get_prev_fchunk(ea)

    if func:
        return func.start_ea
    else:
        return BADADDR


def append_func_tail(funcea, ea1, ea2):
    """
    Append a function chunk to the function

    @param funcea: any address in the function
    @param ea1: start of function tail
    @param ea2: end of function tail
    @return: 0 if failed, 1 if success

    @note: If a chunk exists at the specified addresses, it must have exactly
           the specified boundaries
    """
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        return ida_funcs.append_func_tail(func, ea1, ea2)


def remove_fchunk(funcea, tailea):
    """
    Remove a function chunk from the function

    @param funcea: any address in the function
    @param tailea: any address in the function chunk to remove

    @return: 0 if failed, 1 if success
    """
    func = ida_funcs.get_func(funcea)

    if not func:
        return 0
    else:
        return ida_funcs.remove_func_tail(func, tailea)


def set_tail_owner(tailea, funcea):
    """
    Change the function chunk owner

    @param tailea: any address in the function chunk
    @param funcea: the starting address of the new owner

    @return: False if failed, True if success

    @note: The new owner must already have the chunk appended before the call
    """
    tail = ida_funcs.get_fchunk(tailea)

    if not tail:
        return False
    else:
        return ida_funcs.set_tail_owner(tail, funcea)


def first_func_chunk(funcea):
    """
    Get the first function chunk of the specified function

    @param funcea: any address in the function

    @return: the function entry point or BADADDR

    @note: This function returns the first (main) chunk of the specified function
    """
    func = ida_funcs.get_func(funcea)
    fci = ida_funcs.func_tail_iterator_t(func, funcea)
    if fci.main():
        return fci.chunk().start_ea
    else:
        return BADADDR


def next_func_chunk(funcea, tailea):
    """
    Get the next function chunk of the specified function

    @param funcea: any address in the function
    @param tailea: any address in the current chunk

    @return: the starting address of the next function chunk or BADADDR

    @note: This function returns the next chunk of the specified function
    """
    func = ida_funcs.get_func(funcea)
    fci = ida_funcs.func_tail_iterator_t(func, funcea)
    if not fci.main():
        return BADADDR

    # Iterate and try to find the current chunk
    found = False
    while True:
        if fci.chunk().start_ea <= tailea and \
           fci.chunk().end_ea > tailea:
            found = True
            break
        if not next(fci):
            break

    # Return the next chunk, if there is one
    if found and next(fci):
        return fci.chunk().start_ea
    else:
        return BADADDR


# ----------------------------------------------------------------------------
#                          E N U M S
# ----------------------------------------------------------------------------
get_enum_qty = ida_enum.get_enum_qty
getn_enum = ida_enum.getn_enum
get_enum_idx = ida_enum.get_enum_idx
get_enum = ida_enum.get_enum
get_enum_name = ida_enum.get_enum_name
get_enum_cmt = ida_enum.get_enum_cmt
get_enum_size = ida_enum.get_enum_size
get_enum_width = ida_enum.get_enum_width
get_enum_flag = ida_enum.get_enum_flag
get_enum_member_by_name = ida_enum.get_enum_member_by_name
get_enum_member_value = ida_enum.get_enum_member_value
get_enum_member_bmask = ida_enum.get_enum_member_bmask
get_enum_member_enum = ida_enum.get_enum_member_enum


def get_enum_member(enum_id, value, serial, bmask):
    """
    Get id of constant

    @param enum_id: id of enum
    @param value: value of constant
    @param serial: serial number of the constant in the
              enumeration. See op_enum() for details.
    @param bmask: bitmask of the constant
              ordinary enums accept only ida_enum.DEFMASK as a bitmask

    @return: id of constant or -1 if error
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.get_enum_member(enum_id, value, serial, bmask)


get_first_bmask = ida_enum.get_first_bmask
get_last_bmask = ida_enum.get_last_bmask
get_next_bmask = ida_enum.get_next_bmask
get_prev_bmask = ida_enum.get_prev_bmask


def get_bmask_name(enum_id, bmask):
    """
    Get bitmask name (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant

    @return: name of bitmask or None
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.get_bmask_name(enum_id, bmask)


def get_bmask_cmt(enum_id, bmask, repeatable):
    """
    Get bitmask comment (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant
    @param repeatable: type of comment, 0-regular, 1-repeatable

    @return: comment attached to bitmask or None
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.get_bmask_cmt(enum_id, bmask, repeatable)


def set_bmask_name(enum_id, bmask, name):
    """
    Set bitmask name (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant
    @param name: name of bitmask

    @return: 1-ok, 0-failed
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.set_bmask_name(enum_id, bmask, name)


def set_bmask_cmt(enum_id, bmask, cmt, repeatable):
    """
    Set bitmask comment (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant
    @param cmt: comment
    repeatable - type of comment, 0-regular, 1-repeatable

    @return: 1-ok, 0-failed
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.set_bmask_cmt(enum_id, bmask, cmt, repeatable)


def get_first_enum_member(enum_id, bmask):
    """
    Get first constant in the enum

    @param enum_id: id of enum
    @param bmask: bitmask of the constant (ordinary enums accept only ida_enum.DEFMASK as a bitmask)

    @return: value of constant or idaapi.BADNODE no constants are defined
             All constants are sorted by their values as unsigned longs.
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.get_first_enum_member(enum_id, bmask)


def get_last_enum_member(enum_id, bmask):
    """
    Get last constant in the enum

    @param enum_id: id of enum
    @param bmask: bitmask of the constant (ordinary enums accept only ida_enum.DEFMASK as a bitmask)

    @return: value of constant or idaapi.BADNODE no constants are defined
             All constants are sorted by their values
             as unsigned longs.
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.get_last_enum_member(enum_id, bmask)


def get_next_enum_member(enum_id, value, bmask):
    """
    Get next constant in the enum

    @param enum_id: id of enum
    @param bmask: bitmask of the constant ordinary enums accept only ida_enum.DEFMASK as a bitmask
    @param value: value of the current constant

    @return: value of a constant with value higher than the specified
             value. idaapi.BADNODE no such constants exist.
             All constants are sorted by their values as unsigned longs.
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.get_next_enum_member(enum_id, value, bmask)


def get_prev_enum_member(enum_id, value, bmask):
    """
    Get prev constant in the enum

    @param enum_id: id of enum
    @param bmask  : bitmask of the constant
              ordinary enums accept only ida_enum.DEFMASK as a bitmask
    @param value: value of the current constant

    @return: value of a constant with value lower than the specified
        value. idaapi.BADNODE no such constants exist.
        All constants are sorted by their values as unsigned longs.
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.get_prev_enum_member(enum_id, value, bmask)


def get_enum_member_name(const_id):
    """
    Get name of a constant

    @param const_id: id of const

    Returns: name of constant
    """
    name = ida_enum.get_enum_member_name(const_id)

    if not name:
        return ""
    else:
        return name


def get_enum_member_cmt(const_id, repeatable):
    """
    Get comment of a constant

    @param const_id: id of const
    @param repeatable: 0:get regular comment, 1:get repeatable comment

    @return: comment string
    """
    cmt = ida_enum.get_enum_member_cmt(const_id, repeatable)

    if not cmt:
        return ""
    else:
        return cmt


def add_enum(idx, name, flag):
    """
    Add a new enum type

    @param idx: serial number of the new enum.
            If another enum with the same serial number
            exists, then all enums with serial
            numbers >= the specified idx get their
            serial numbers incremented (in other words,
            the new enum is put in the middle of the list of enums).

            If idx >= get_enum_qty() or idx == idaapi.BADNODE
            then the new enum is created at the end of
            the list of enums.

    @param name: name of the enum.
    @param flag: flags for representation of numeric constants
                 in the definition of enum.

    @return: id of new enum or BADADDR
    """
    if idx < 0:
        idx = idx & SIZE_MAX
    return ida_enum.add_enum(idx, name, flag)


del_enum = ida_enum.del_enum
set_enum_idx = ida_enum.set_enum_idx
set_enum_name = ida_enum.set_enum_name
set_enum_cmt = ida_enum.set_enum_cmt
set_enum_flag = ida_enum.set_enum_flag
set_enum_bf = ida_enum.set_enum_bf
set_enum_width = ida_enum.set_enum_width
is_bf = ida_enum.is_bf


def add_enum_member(enum_id, name, value, bmask):
    """
    Add a member of enum - a symbolic constant

    @param enum_id: id of enum
    @param name: name of symbolic constant. Must be unique in the program.
    @param value: value of symbolic constant.
    @param bmask: bitmask of the constant
        ordinary enums accept only ida_enum.DEFMASK as a bitmask
        all bits set in value should be set in bmask too

    @return: 0-ok, otherwise error code (one of ENUM_MEMBER_ERROR_*)
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.add_enum_member(enum_id, name, value, bmask)


ENUM_MEMBER_ERROR_NAME  = ida_enum.ENUM_MEMBER_ERROR_NAME  # already have member with this name (bad name)
ENUM_MEMBER_ERROR_VALUE = ida_enum.ENUM_MEMBER_ERROR_VALUE # already have member with this value
ENUM_MEMBER_ERROR_ENUM  = ida_enum.ENUM_MEMBER_ERROR_ENUM  # bad enum id
ENUM_MEMBER_ERROR_MASK  = ida_enum.ENUM_MEMBER_ERROR_MASK  # bad bmask
ENUM_MEMBER_ERROR_ILLV  = ida_enum.ENUM_MEMBER_ERROR_ILLV  # bad bmask and value combination (~bmask & value != 0)


def del_enum_member(enum_id, value, serial, bmask):
    """
    Delete a member of enum - a symbolic constant

    @param enum_id: id of enum
    @param value: value of symbolic constant.
    @param serial: serial number of the constant in the
        enumeration. See op_enum() for for details.
    @param bmask: bitmask of the constant ordinary enums accept
        only ida_enum.DEFMASK as a bitmask

    @return: 1-ok, 0-failed
    """
    if bmask < 0:
        bmask &= BADADDR
    return ida_enum.del_enum_member(enum_id, value, serial, bmask)


set_enum_member_name = ida_enum.set_enum_member_name
set_enum_member_cmt = ida_enum.set_enum_member_cmt

#----------------------------------------------------------------------------
#                         A R R A Y S  I N  I D C
#----------------------------------------------------------------------------

_IDC_ARRAY_PREFIX = "$ idc_array "
def __l2m1(v):
    """
    Long to minus 1: If the 'v' appears to be the
    'signed long' version of -1, then return -1.
    Otherwise, return 'v'.
    """
    if v == ida_netnode.BADNODE:
        return -1
    else:
        return v


def __m1tol(v):
    """
    Long -1 to BADNODE: If the 'v' appears to be the
    'signed long' version of -1, then return BADNODE.
    Otherwise, return 'v'.
    """
    if v == -1:
        return ida_netnode.BADNODE 
    else:
        return v


AR_LONG = ida_netnode.atag
"""Array of longs"""

AR_STR = ida_netnode.stag
"""Array of strings"""


class __dummy_netnode(object):
    """
    Implements, in an "always failing" fashion, the
    netnode functions that are necessary for the
    array-related functions.

    The sole purpose of this singleton class is to
    serve as a placeholder for netnode-manipulating
    functions, that don't want to each have to perform
    checks on the existence of the netnode.
    (..in other words: it avoids a bunch of if/else's).

    See __GetArrayById() for more info.
    """
    def rename(self, *args): return 0
    def kill(self, *args): pass
    def index(self, *args): return -1
    def altset(self, *args): return 0
    def supset(self, *args): return 0
    def altval(self, *args): return 0
    def supval(self, *args): return 0
    def altdel(self, *args): return 0
    def supdel(self, *args): return 0
    def altfirst(self, *args): return -1
    def supfirst(self, *args): return -1
    def altlast(self, *args): return -1
    def suplast(self, *args): return -1
    def altnext(self, *args): return -1
    def supnext(self, *args): return -1
    def altprev(self, *args): return -1
    def supprev(self, *args): return -1
    def hashset(self, *args): return 0
    def hashval(self, *args): return 0
    def hashstr(self, *args): return 0
    def hashstr_buf(self, *args): return 0
    def hashset_idx(self, *args): return 0
    def hashset_buf(self, *args): return 0
    def hashval_long(self, *args): return 0
    def hashdel(self, *args): return 0
    def hashfirst(self, *args): return 0
    def hashnext(self, *args): return 0
    def hashprev(self, *args): return 0
    def hashlast(self, *args): return 0
__dummy_netnode.instance = __dummy_netnode()



def __GetArrayById(array_id):
    """
    Get an array, by its ID.

    This (internal) wrapper around 'idaaip.netnode(array_id)'
    will ensure a certain safety around the retrieval of
    arrays (by catching quite unexpect[ed|able] exceptions,
    and making sure we don't create & use `transient' netnodes).

    @param array_id: A positive, valid array ID.
    """
    try:
        node = ida_netnode.netnode(array_id)
        nodename = node.get_name()
        if nodename is None or not nodename.startswith(_IDC_ARRAY_PREFIX):
            return __dummy_netnode.instance
        else:
            return node
    except TypeError:
        return __dummy_netnode.instance
    except NotImplementedError:
        return __dummy_netnode.instance


def create_array(name):
    """
    Create array.

    @param name: The array name.

    @return: -1 in case of failure, a valid array_id otherwise.
    """
    node = ida_netnode.netnode()
    res  = node.create(_IDC_ARRAY_PREFIX + name)
    if res == False:
        return -1
    else:
        return node.index()


def get_array_id(name):
    """
    Get array array_id, by name.

    @param name: The array name.

    @return: -1 in case of failure (i.e., no array with that
             name exists), a valid array_id otherwise.
    """
    return __l2m1(ida_netnode.netnode(_IDC_ARRAY_PREFIX + name, 0, False).index())


def rename_array(array_id, newname):
    """
    Rename array, by its ID.

    @param id: The ID of the array to rename.
    @param newname: The new name of the array.

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(array_id).rename(_IDC_ARRAY_PREFIX + newname) == 1


def delete_array(array_id):
    """
    Delete array, by its ID.

    @param array_id: The ID of the array to delete.
    """
    __GetArrayById(array_id).kill()


def set_array_long(array_id, idx, value):
    """
    Sets the long value of an array element.

    @param array_id: The array ID.
    @param idx: Index of an element.
    @param value: 32bit or 64bit value to store in the array

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(array_id).altset(idx, value)


def set_array_string(array_id, idx, value):
    """
    Sets the string value of an array element.

    @param array_id: The array ID.
    @param idx: Index of an element.
    @param value: String value to store in the array

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(array_id).supset(idx, value)


def get_array_element(tag, array_id, idx):
    """
    Get value of array element.

    @param tag: Tag of array, specifies one of two array types: AR_LONG, AR_STR
    @param array_id: The array ID.
    @param idx: Index of an element.

    @return: Value of the specified array element. Note that
             this function may return char or long result. Unexistent
             array elements give zero as a result.
    """
    node = __GetArrayById(array_id)
    if tag == AR_LONG:
        return node.altval(idx, tag)
    elif tag == AR_STR:
        res = node.supval(idx, tag)
        return 0 if res is None else res
    else:
        return 0


def del_array_element(tag, array_id, idx):
    """
    Delete an array element.

    @param tag: Tag of array, specifies one of two array types: AR_LONG, AR_STR
    @param array_id: The array ID.
    @param idx: Index of an element.

    @return: 1 in case of success, 0 otherwise.
    """
    node = __GetArrayById(array_id)
    if tag == AR_LONG:
        return node.altdel(idx, tag)
    elif tag == AR_STR:
        return node.supdel(idx, tag)
    else:
        return 0


def get_first_index(tag, array_id):
    """
    Get index of the first existing array element.

    @param tag: Tag of array, specifies one of two array types: AR_LONG, AR_STR
    @param array_id: The array ID.

    @return: -1 if the array is empty, otherwise index of first array
             element of given type.
    """
    node = __GetArrayById(array_id)
    if tag == AR_LONG:
        return __l2m1(node.altfirst(tag))
    elif tag == AR_STR:
        return __l2m1(node.supfirst(tag))
    else:
        return -1


def get_last_index(tag, array_id):
    """
    Get index of last existing array element.

    @param tag: Tag of array, specifies one of two array types: AR_LONG, AR_STR
    @param array_id: The array ID.

    @return: -1 if the array is empty, otherwise index of first array
             element of given type.
    """
    node = __GetArrayById(array_id)
    if tag == AR_LONG:
        return __l2m1(node.altlast(tag))
    elif tag == AR_STR:
        return __l2m1(node.suplast(tag))
    else:
        return -1


def get_next_index(tag, array_id, idx):
    """
    Get index of the next existing array element.

    @param tag: Tag of array, specifies one of two array types: AR_LONG, AR_STR
    @param array_id: The array ID.
    @param idx: Index of the current element.

    @return: -1 if no more elements, otherwise returns index of the
             next array element of given type.
    """
    node = __GetArrayById(array_id)
    try:
        if tag == AR_LONG:
            return __l2m1(node.altnext(__m1tol(idx), tag))
        elif tag == AR_STR:
            return __l2m1(node.supnext(__m1tol(idx), tag))
        else:
            return -1
    except OverflowError:
        # typically: An index of -1 was passed.
        return -1


def get_prev_index(tag, array_id, idx):
    """
    Get index of the previous existing array element.

    @param tag: Tag of array, specifies one of two array types: AR_LONG, AR_STR
    @param array_id: The array ID.
    @param idx: Index of the current element.

    @return: -1 if no more elements, otherwise returns index of the
             previous array element of given type.
    """
    node = __GetArrayById(array_id)
    try:
        if tag == AR_LONG:
            return __l2m1(node.altprev(__m1tol(idx), tag))
        elif tag == AR_STR:
            return __l2m1(node.supprev(__m1tol(idx), tag))
        else:
            return -1
    except OverflowError:
        # typically: An index of -1 was passed.
        return -1


# -------------------- hashes -----------------------

def set_hash_long(hash_id, key, value):
    """
    Sets the long value of a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element.
    @param value: 32bit or 64bit value to store in the hash

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(hash_id).hashset_idx(key, value)


def get_hash_long(hash_id, key):
    """
    Gets the long value of a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element.

    @return: the 32bit or 64bit value of the element, or 0 if no such
             element.
    """
    return __GetArrayById(hash_id).hashval_long(key);


def set_hash_string(hash_id, key, value):
    """
    Sets the string value of a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element.
    @param value: string value to store in the hash

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(hash_id).hashset_buf(key, value)


def get_hash_string(hash_id, key):
    """
    Gets the string value of a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element.

    @return: the string value of the element, or None if no such
             element.
    """
    return __GetArrayById(hash_id).hashstr_buf(key);


def del_hash_string(hash_id, key):
    """
    Delete a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element

    @return: 1 upon success, 0 otherwise.
    """
    return __GetArrayById(hash_id).hashdel(key)


def get_first_hash_key(hash_id):
    """
    Get the first key in the hash.

    @param hash_id: The hash ID.

    @return: the key, 0 otherwise.
    """
    r = __GetArrayById(hash_id).hashfirst()
    return 0 if r is None else r


def get_last_hash_key(hash_id):
    """
    Get the last key in the hash.

    @param hash_id: The hash ID.

    @return: the key, 0 otherwise.
    """
    r = __GetArrayById(hash_id).hashlast()
    return 0 if r is None else r


def get_next_hash_key(hash_id, key):
    """
    Get the next key in the hash.

    @param hash_id: The hash ID.
    @param key: The current key.

    @return: the next key, 0 otherwise
    """
    r = __GetArrayById(hash_id).hashnext(key)
    return 0 if r is None else r


def get_prev_hash_key(hash_id, key):
    """
    Get the previous key in the hash.

    @param hash_id: The hash ID.
    @param key: The current key.

    @return: the previous key, 0 otherwise
    """
    r = __GetArrayById(hash_id).hashprev(key)
    return 0 if r is None else r




#----------------------------------------------------------------------------
#                 S O U R C E   F I L E / L I N E   N U M B E R S
#----------------------------------------------------------------------------
add_sourcefile = ida_lines.add_sourcefile
get_sourcefile = ida_lines.get_sourcefile
del_sourcefile = ida_lines.del_sourcefile

set_source_linnum = ida_nalt.set_source_linnum
get_source_linnum = ida_nalt.get_source_linnum
del_source_linnum = ida_nalt.del_source_linnum


#----------------------------------------------------------------------------
#                T Y P E  L I B R A R I E S
#----------------------------------------------------------------------------

def add_default_til(name):
    """
    Load a type library

    @param name: name of type library.
    @return: 1-ok, 0-failed.
    """
    til = ida_typeinf.add_til(name, ida_typeinf.ADDTIL_DEFAULT)
    if til:
        return 1
    else:
        return 0


def import_type(idx, type_name):
    """
    Copy information from type library to database
    Copy structure, union, or enum definition from the type library
    to the IDA database.

    @param idx: the position of the new type in the list of
                types (structures or enums) -1 means at the end of the list
    @param type_name: name of type to copy

    @return: BADNODE-failed, otherwise the type id (structure id or enum id)
    """
    return ida_typeinf.import_type(None, idx, type_name)


def get_type(ea):
    """
    Get type of function/variable

    @param ea: the address of the object

    @return: type string or None if failed
    """
    return ida_typeinf.idc_get_type(ea)

def SizeOf(typestr):
    """
    Returns the size of the type. It is equivalent to IDC's sizeof().
    Use name, tp, fld = idc.parse_decl() ; SizeOf(tp) to retrieve the size
    @return: -1 if typestring is not valid otherwise the size of the type
    """
    return ida_typeinf.calc_type_size(None, typestr)

def get_tinfo(ea):
    """
    Get type information of function/variable as 'typeinfo' object

    @param ea: the address of the object
    @return: None on failure, or (type, fields) tuple.
    """
    return ida_typeinf.idc_get_type_raw(ea)

def get_local_tinfo(ordinal):
    """
    Get local type information as 'typeinfo' object

    @param ordinal:  slot number (1...NumberOfLocalTypes)
    @return: None on failure, or (type, fields) tuple.
    """
    return ida_typeinf.idc_get_local_type_raw(ordinal)

def guess_type(ea):
    """
    Guess type of function/variable

    @param ea: the address of the object, can be the structure member id too

    @return: type string or None if failed
    """
    return ida_typeinf.idc_guess_type(ea)

TINFO_GUESSED   = 0x0000 # this is a guessed type
TINFO_DEFINITE  = 0x0001 # this is a definite type
TINFO_DELAYFUNC = 0x0002 # if type is a function and no function exists at ea,
                         # schedule its creation and argument renaming to
                         # auto-analysis otherwise try to create it immediately

def apply_type(ea, py_type, flags = TINFO_DEFINITE):
    """
    Apply the specified type to the address

    @param ea: the address of the object
    @param py_type: typeinfo tuple (type, fields) as get_tinfo() returns
                 or tuple (name, type, fields) as parse_decl() returns
                 or None
                if specified as None, then the
                item associated with 'ea' will be deleted.
    @param flags: combination of TINFO_... constants or 0
    @return: Boolean
    """

    if py_type is None:
        py_type = ""
    if isinstance(py_type, ida_idaapi.string_types) and len(py_type) == 0:
        pt = (b"", b"")
    else:
        if len(py_type) == 3:
          pt = py_type[1:]      # skip name component
        else:
          pt = py_type
    return ida_typeinf.apply_type(None, pt[0], pt[1], ea, flags)


PT_SIL      = ida_typeinf.PT_SIL      # silent, no messages
PT_NDC      = ida_typeinf.PT_NDC      # don't decorate names
PT_TYP      = ida_typeinf.PT_TYP      # return declared type information
PT_VAR      = ida_typeinf.PT_VAR      # return declared object information
PT_PACKMASK = ida_typeinf.PT_PACKMASK # mask for pack alignment values
PT_HIGH     = ida_typeinf.PT_HIGH     # assume high level prototypes (with hidden args, etc)
PT_LOWER    = ida_typeinf.PT_LOWER    # lower the function prototypes
PT_REPLACE  = ida_typeinf.PT_REPLACE  # replace the old type (used in idc)
PT_RAWARGS  = ida_typeinf.PT_RAWARGS  # leave argument names unchanged (do not remove underscores)

PT_SILENT = PT_SIL # alias
PT_PAKDEF = 0x0000 # default pack value
PT_PAK1   = 0x0010 # #pragma pack(1)
PT_PAK2   = 0x0020 # #pragma pack(2)
PT_PAK4   = 0x0030 # #pragma pack(4)
PT_PAK8   = 0x0040 # #pragma pack(8)
PT_PAK16  = 0x0050 # #pragma pack(16)

# idc.py-specific
PT_FILE = 0x00010000 # input if a file name (otherwise contains type declarations)


def SetType(ea, newtype):
    """
    Set type of function/variable

    @param ea: the address of the object
    @param newtype: the type string in C declaration form.
                Must contain the closing ';'
                if specified as an empty string, then the
                item associated with 'ea' will be deleted.

    @return: 1-ok, 0-failed.
    """
    if newtype != '':
        pt = parse_decl(newtype, PT_SIL)
        if pt is None:
          # parsing failed
          return None
    else:
        pt = None
    return apply_type(ea, pt, TINFO_DEFINITE)

def parse_decl(inputtype, flags):
    """
    Parse type declaration

    @param inputtype: file name or C declarations (depending on the flags)
    @param flags: combination of PT_... constants or 0

    @return: None on failure or (name, type, fields) tuple
    """
    if len(inputtype) != 0 and inputtype[-1] != ';':
        inputtype = inputtype + ';'
    return ida_typeinf.idc_parse_decl(None, inputtype, flags)

def parse_decls(inputtype, flags = 0):
    """
    Parse type declarations

    @param inputtype: file name or C declarations (depending on the flags)
    @param flags: combination of PT_... constants or 0

    @return: number of parsing errors (0 no errors)
    """
    return ida_typeinf.idc_parse_types(inputtype, flags)


def print_decls(ordinals, flags):
    """
    Print types in a format suitable for use in a header file

    @param ordinals: comma-separated list of type ordinals
    @param flags: combination of PDF_... constants or 0

    @return: string containing the type definitions
    """
    class def_sink(ida_typeinf.text_sink_t):

        def __init__(self):
            ida_typeinf.text_sink_t.__init__(self)
            self.text = ""

        def _print(self, defstr):
            self.text += defstr
            return 0

    sink = def_sink()
    py_ordinals = list(map(lambda l : int(l), ordinals.split(",")))
    ida_typeinf.print_decls(sink, None, py_ordinals, flags)

    return sink.text


PDF_INCL_DEPS  = 0x1  # include dependencies
PDF_DEF_FWD    = 0x2  # allow forward declarations
PDF_DEF_BASE   = 0x4  # include base types: __int8, __int16, etc..
PDF_HEADER_CMT = 0x8  # prepend output with a descriptive comment


def get_ordinal_qty():
    """
    Get number of local types + 1

    @return: value >= 1. 1 means that there are no local types.
    """
    return ida_typeinf.get_ordinal_qty(None)


def set_local_type(ordinal, input, flags):
    """
    Parse one type declaration and store it in the specified slot

    @param ordinal:  slot number (1...NumberOfLocalTypes)
                     -1 means allocate new slot or reuse the slot
                     of the existing named type
    @param input:  C declaration. Empty input empties the slot
    @param flags:  combination of PT_... constants or 0

    @return: slot number or 0 if error
    """
    return ida_typeinf.idc_set_local_type(ordinal, input, flags)


def GetLocalType(ordinal, flags):
    """
    Retrieve a local type declaration
    @param flags: any of PRTYPE_* constants
    @return: local type as a C declaration or ""
    """
    (type, fields) = get_local_tinfo(ordinal)
    if type:
      name = get_numbered_type_name(ordinal)
      return ida_typeinf.idc_print_type(type, fields, name, flags)
    return ""

PRTYPE_1LINE  = 0x0000 # print to one line
PRTYPE_MULTI  = 0x0001 # print to many lines
PRTYPE_TYPE   = 0x0002 # print type declaration (not variable declaration)
PRTYPE_PRAGMA = 0x0004 # print pragmas for alignment


def get_numbered_type_name(ordinal):
    """
    Retrieve a local type name

    @param ordinal:  slot number (1...NumberOfLocalTypes)

    returns: local type name or None
    """
    return ida_typeinf.idc_get_local_type_name(ordinal)


# ----------------------------------------------------------------------------
#                           H I D D E N  A R E A S
# ----------------------------------------------------------------------------
add_hidden_range = ida_bytes.add_hidden_range

def update_hidden_range(ea, visible):
    """
    Set hidden range state

    @param ea:      any address belonging to the hidden range
    @param visible: new state of the range

    @return: != 0 - ok
    """
    ha = ida_bytes.get_hidden_range(ea)

    if not ha:
        return 0
    else:
        ha.visible = visible
        return ida_bytes.update_hidden_range(ha)


del_hidden_range = ida_bytes.del_hidden_range


#--------------------------------------------------------------------------
#                   D E B U G G E R  I N T E R F A C E
#--------------------------------------------------------------------------
load_debugger = ida_dbg.load_debugger
start_process = ida_dbg.start_process
exit_process = ida_dbg.exit_process
suspend_process = ida_dbg.suspend_process
get_processes = ida_dbg.get_processes
attach_process = ida_dbg.attach_process
detach_process = ida_dbg.detach_process
get_thread_qty = ida_dbg.get_thread_qty
getn_thread = ida_dbg.getn_thread
get_current_thread = ida_dbg.get_current_thread
getn_thread_name = ida_dbg.getn_thread_name
select_thread = ida_dbg.select_thread
suspend_thread = ida_dbg.suspend_thread
resume_thread = ida_dbg.resume_thread


def _get_modules():
    """
    INTERNAL: Enumerate process modules
    """
    module = ida_idd.modinfo_t()
    result = ida_dbg.get_first_module(module)
    while result:
        yield module
        result = ida_dbg.get_next_module(module)


def get_first_module():
    """
    Enumerate process modules

    @return: first module's base address or None on failure
    """
    for module in _get_modules():
        return module.base
    else:
        return None


def get_next_module(base):
    """
    Enumerate process modules

    @param base: previous module's base address

    @return: next module's base address or None on failure
    """
    foundit = False
    for module in _get_modules():
        if foundit:
            return module.base
        if module.base == base:
            foundit = True
    else:
        return None


def get_module_name(base):
    """
    Get process module name

    @param base: the base address of the module

    @return: required info or None
    """
    for module in _get_modules():
        if module.base == base:
            return module.name
    else:
        return 0


def get_module_size(base):
    """
    Get process module size

    @param base: the base address of the module

    @return: required info or -1
    """
    for module in _get_modules():
        if module.base == base:
            return module.size
    else:
        return -1


step_into = ida_dbg.step_into
step_over = ida_dbg.step_over
run_to = ida_dbg.run_to
step_until_ret = ida_dbg.step_until_ret


wait_for_next_event = ida_dbg.wait_for_next_event


def resume_process():
    return wait_for_next_event(WFNE_CONT|WFNE_NOWAIT, 0)

def send_dbg_command(cmd):
    """Sends a command to the debugger module and returns the output string.
    An exception will be raised if the debugger is not running or the current debugger does not export
    the 'send_dbg_command' IDC command.
    """
    s = eval_idc('send_dbg_command("%s");' % ida_kernwin.str2user(cmd))
    if s.startswith("IDC_FAILURE"):
        raise Exception("Debugger command is available only when the debugger is active!")
    return s

# wfne flag is combination of the following:
WFNE_ANY    = 0x0001 # return the first event (even if it doesn't suspend the process)
                     # if the process is still running, the database
                     # does not reflect the memory state. you might want
                     # to call refresh_debugger_memory() in this case
WFNE_SUSP   = 0x0002 # wait until the process gets suspended
WFNE_SILENT = 0x0004 # 1: be slient, 0:display modal boxes if necessary
WFNE_CONT   = 0x0008 # continue from the suspended state
WFNE_NOWAIT = 0x0010 # do not wait for any event, immediately return DEC_TIMEOUT
                     # (to be used with WFNE_CONT)

# debugger event codes
NOTASK            = -2         # process does not exist
DBG_ERROR         = -1         # error (e.g. network problems)
DBG_TIMEOUT       = 0          # timeout
PROCESS_STARTED   = 0x00000001 # New process started
PROCESS_EXITED    = 0x00000002 # Process stopped
THREAD_STARTED    = 0x00000004 # New thread started
THREAD_EXITED     = 0x00000008 # Thread stopped
BREAKPOINT        = 0x00000010 # Breakpoint reached
STEP              = 0x00000020 # One instruction executed
EXCEPTION         = 0x00000040 # Exception
LIB_LOADED        = 0x00000080 # New library loaded
LIB_UNLOADED      = 0x00000100 # Library unloaded
INFORMATION       = 0x00000200 # User-defined information
PROCESS_ATTACHED  = 0x00000400 # Attached to running process
PROCESS_DETACHED  = 0x00000800 # Detached from process
PROCESS_SUSPENDED = 0x00001000 # Process has been suspended


refresh_debugger_memory = ida_dbg.refresh_debugger_memory

take_memory_snapshot = ida_segment.take_memory_snapshot

get_process_state = ida_dbg.get_process_state

DSTATE_SUSP            = -1 # process is suspended
DSTATE_NOTASK          =  0 # no process is currently debugged
DSTATE_RUN             =  1 # process is running
DSTATE_RUN_WAIT_ATTACH =  2 # deprecated
DSTATE_RUN_WAIT_END    =  3 # deprecated

"""
 Get various information about the current debug event
 These functions are valid only when the current event exists
 (the process is in the suspended state)
"""

# For all events:

def get_event_id():
    """
    Get ID of debug event

    @return: event ID
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.eid()


def get_event_pid():
    """
    Get process ID for debug event

    @return: process ID
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.pid


def get_event_tid():
    """
    Get type ID for debug event

    @return: type ID
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.tid


def get_event_ea():
    """
    Get ea for debug event

    @return: ea
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.ea


def is_event_handled():
    """
    Is the debug event handled?

    @return: boolean
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.handled


# For PROCESS_STARTED, PROCESS_ATTACHED, LIB_LOADED events:

def get_event_module_name():
    """
    Get module name for debug event

    @return: module name
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ida_idd.get_event_module_name(ev)


def get_event_module_base():
    """
    Get module base for debug event

    @return: module base
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ida_idd.get_event_module_base(ev)


def get_event_module_size():
    """
    Get module size for debug event

    @return: module size
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ida_idd.get_event_module_size(ev)


def get_event_exit_code():
    """
    Get exit code for debug event

    @return: exit code for PROCESS_EXITED, THREAD_EXITED events
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.exit_code()


def get_event_info():
    """
    Get debug event info

    @return: event info: for THREAD_STARTED (thread name)
                         for LIB_UNLOADED (unloaded library name)
                         for INFORMATION (message to display)
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ida_idd.get_event_info(ev)


def get_event_bpt_hea():
    """
    Get hardware address for BREAKPOINT event

    @return: hardware address
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ida_idd.get_event_bpt_hea(ev)


def get_event_exc_code():
    """
    Get exception code for EXCEPTION event

    @return: exception code
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ida_idd.get_event_exc_code(ev)


def get_event_exc_ea():
    """
    Get address for EXCEPTION event

    @return: adress of exception
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ida_idd.get_event_exc_ea(ev)


def can_exc_continue():
    """
    Can it continue after EXCEPTION event?

    @return: boolean
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ida_idd.can_exc_continue(ev)


def get_event_exc_info():
    """
    Get info for EXCEPTION event

    @return: info string
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ida_idd.get_event_exc_info(ev)


set_debugger_options = ida_dbg.set_debugger_options


DOPT_SEGM_MSGS    = 0x00000001 # print messages on debugger segments modifications
DOPT_START_BPT    = 0x00000002 # break on process start
DOPT_THREAD_MSGS  = 0x00000004 # print messages on thread start/exit
DOPT_THREAD_BPT   = 0x00000008 # break on thread start/exit
DOPT_BPT_MSGS     = 0x00000010 # print message on breakpoint
DOPT_LIB_MSGS     = 0x00000040 # print message on library load/unlad
DOPT_LIB_BPT      = 0x00000080 # break on library load/unlad
DOPT_INFO_MSGS    = 0x00000100 # print message on debugging information
DOPT_INFO_BPT     = 0x00000200 # break on debugging information
DOPT_REAL_MEMORY  = 0x00000400 # don't hide breakpoint instructions
DOPT_REDO_STACK   = 0x00000800 # reconstruct the stack
DOPT_ENTRY_BPT    = 0x00001000 # break on program entry point
DOPT_EXCDLG       = 0x00006000 # exception dialogs:

EXCDLG_NEVER      = 0x00000000 # never display exception dialogs
EXCDLG_UNKNOWN    = 0x00002000 # display for unknown exceptions
EXCDLG_ALWAYS     = 0x00006000 # always display

DOPT_LOAD_DINFO   = 0x00008000 # automatically load debug files (pdb)


get_debugger_event_cond = ida_dbg.get_debugger_event_cond
set_debugger_event_cond = ida_dbg.set_debugger_event_cond

set_remote_debugger = ida_dbg.set_remote_debugger

define_exception = ida_dbg.define_exception

EXC_BREAK  = 0x0001 # break on the exception
EXC_HANDLE = 0x0002 # should be handled by the debugger?

get_reg_value = ida_dbg.get_reg_val

def set_reg_value(value, name):
    """
    Set register value

    @param name: the register name
    @param value: new register value

    @note: The debugger should be running
           It is not necessary to use this function to set register values.
           A register name in the left side of an assignment will do too.
    """
    return ida_dbg.set_reg_val(name, value)


get_bpt_qty = ida_dbg.get_bpt_qty


def get_bpt_ea(n):
    """
    Get breakpoint address

    @param n: number of breakpoint, is in range 0..get_bpt_qty()-1

    @return: address of the breakpoint or BADADDR
    """
    bpt = ida_dbg.bpt_t()

    if ida_dbg.getn_bpt(n, bpt):
        return bpt.ea
    else:
        return BADADDR


def get_bpt_attr(ea, bptattr):
    """
    Get the characteristics of a breakpoint

    @param ea: any address in the breakpoint range
    @param bptattr: the desired attribute code, one of BPTATTR_... constants

    @return: the desired attribute value or -1
    """
    bpt = ida_dbg.bpt_t()

    if not ida_dbg.get_bpt(ea, bpt):
        return -1
    else:
        if bptattr == BPTATTR_EA:
            return bpt.ea
        if bptattr == BPTATTR_SIZE:
            return bpt.size
        if bptattr == BPTATTR_TYPE:
            return bpt.type
        if bptattr == BPTATTR_COUNT:
            return bpt.pass_count
        if bptattr == BPTATTR_FLAGS:
            return bpt.flags
        if bptattr == BPTATTR_COND:
            return bpt.condition
        if bptattr == BPTATTR_PID:
            return bpt.pid
        if bptattr == BPTATTR_TID:
            return bpt.tid
        return -1


BPTATTR_EA    =  1   # starting address of the breakpoint
BPTATTR_SIZE  =  2   # size of the breakpoint (undefined for software breakpoint)

# type of the breakpoint
BPTATTR_TYPE  =  3

# Breakpoint types:
BPT_WRITE    = 1                     # Hardware: Write access
BPT_RDWR     = 3                     # Hardware: Read/write access
BPT_SOFT     = 4                     # Software breakpoint
BPT_EXEC     = 8                     # Hardware: Execute instruction
BPT_DEFAULT  = (BPT_SOFT|BPT_EXEC);  # Choose bpt type automaticaly

BPTATTR_COUNT  =  4
BPTATTR_FLAGS  =  5
BPT_BRK        = 0x001 # the debugger stops on this breakpoint
BPT_TRACE      = 0x002 # the debugger adds trace information when this breakpoint is reached
BPT_UPDMEM     = 0x004 # refresh the memory layout and contents before evaluating bpt condition
BPT_ENABLED    = 0x008 # enabled?
BPT_LOWCND     = 0x010 # condition is calculated at low level (on the server side)
BPT_TRACEON    = 0x020 # enable tracing when the breakpoint is reached
BPT_TRACE_INSN = 0x040 #   instruction tracing
BPT_TRACE_FUNC = 0x080 #   function tracing
BPT_TRACE_BBLK = 0x100 #   basic block tracing

BPTATTR_COND  =  6   # Breakpoint condition. NOTE: the return value is a string in this case
BPTATTR_PID   =  7   # Brekapoint process id
BPTATTR_TID   =  8   # Brekapoint thread id

# Breakpoint location type:
BPLT_ABS  =  0   # Absolute address. Attributes:
                 # - locinfo: absolute address

BPLT_REL  =  1   # Module relative address. Attributes:
                 # - locpath: the module path
                 # - locinfo: offset from the module base address

BPLT_SYM  =  2   # Symbolic name. The name will be resolved on DLL load/unload
                 # events and on naming an address. Attributes:
                 # - locpath: symbol name
                 # - locinfo: offset from the symbol base address


def set_bpt_attr(address, bptattr, value):
    """
        modifiable characteristics of a breakpoint

    @param address: any address in the breakpoint range
    @param bptattr: the attribute code, one of BPTATTR_* constants
                    BPTATTR_CND is not allowed, see set_bpt_cond()
    @param value: the attibute value

    @return: success
    """
    bpt = ida_dbg.bpt_t()

    if not ida_dbg.get_bpt(address, bpt):
        return False
    else:
        if bptattr not in [ BPTATTR_SIZE, BPTATTR_TYPE, BPTATTR_FLAGS, BPTATTR_COUNT, BPTATTR_PID, BPTATTR_TID ]:
            return False
        if bptattr == BPTATTR_SIZE:
            bpt.size = value
        if bptattr == BPTATTR_TYPE:
            bpt.type = value
        if bptattr == BPTATTR_COUNT:
            bpt.pass_count = value
        if bptattr == BPTATTR_FLAGS:
            bpt.flags = value
        if bptattr == BPTATTR_PID:
            bpt.pid = value
        if bptattr == BPTATTR_TID:
            bpt.tid = value

        return ida_dbg.update_bpt(bpt)


def set_bpt_cond(ea, cnd, is_lowcnd=0):
    """
    Set breakpoint condition

    @param ea: any address in the breakpoint range
    @param cnd: breakpoint condition
    @param is_lowcnd: 0 - regular condition, 1 - low level condition

    @return: success
    """
    bpt = ida_dbg.bpt_t()

    if not ida_dbg.get_bpt(ea, bpt):
        return False

    bpt.condition = cnd
    if is_lowcnd:
        bpt.flags |= BPT_LOWCND
    else:
        bpt.flags &= ~BPT_LOWCND

    return ida_dbg.update_bpt(bpt)


add_bpt    = ida_dbg.add_bpt
del_bpt    = ida_dbg.del_bpt
enable_bpt = ida_dbg.enable_bpt
check_bpt  = ida_dbg.check_bpt

BPTCK_NONE = -1  # breakpoint does not exist
BPTCK_NO   =  0  # breakpoint is disabled
BPTCK_YES  =  1  # breakpoint is enabled
BPTCK_ACT  =  2  # breakpoint is active (written to the process)


def enable_tracing(trace_level, enable):
    """
    Enable step tracing

    @param trace_level:  what kind of trace to modify
    @param enable: 0: turn off, 1: turn on

    @return: success
    """
    assert trace_level in [ TRACE_STEP, TRACE_INSN, TRACE_FUNC ], \
        "trace_level must be one of TRACE_* constants"

    if trace_level == TRACE_STEP:
        return ida_dbg.enable_step_trace(enable)

    if trace_level == TRACE_INSN:
        return ida_dbg.enable_insn_trace(enable)

    if trace_level == TRACE_FUNC:
        return ida_dbg.enable_func_trace(enable)

    return False

TRACE_STEP = 0x0  # lowest level trace. trace buffers are not maintained
TRACE_INSN = 0x1  # instruction level trace
TRACE_FUNC = 0x2  # function level trace (calls & rets)


get_step_trace_options = ida_dbg.get_step_trace_options
set_step_trace_options = ida_dbg.set_step_trace_options


ST_OVER_DEBUG_SEG = 0x01 # step tracing will be disabled when IP is in a debugger segment
ST_OVER_LIB_FUNC  = 0x02 # step tracing will be disabled when IP is in a library function
ST_ALREADY_LOGGED = 0x04 # step tracing will be disabled when IP is already logged
ST_SKIP_LOOPS     = 0x08 # step tracing will try to skip loops already recorded

load_trace_file = ida_dbg.load_trace_file
save_trace_file = ida_dbg.save_trace_file
is_valid_trace_file = ida_dbg.is_valid_trace_file
diff_trace_file = ida_dbg.diff_trace_file

def clear_trace(filename):
    """
    Clear the current trace buffer
    """
    return ida_dbg.clear_trace()

get_trace_file_desc = ida_dbg.get_trace_file_desc
set_trace_file_desc = ida_dbg.set_trace_file_desc
get_tev_qty = ida_dbg.get_tev_qty
get_tev_ea = ida_dbg.get_tev_ea

TEV_NONE  = 0 # no event
TEV_INSN  = 1 # an instruction trace
TEV_CALL  = 2 # a function call trace
TEV_RET   = 3 # a function return trace
TEV_BPT   = 4 # write, read/write, execution trace
TEV_MEM   = 5 # memory layout changed
TEV_EVENT = 6 # debug event

get_tev_type = ida_dbg.get_tev_type
get_tev_tid = ida_dbg.get_tev_tid
get_tev_reg = ida_dbg.get_tev_reg_val
get_tev_mem_qty = ida_dbg.get_tev_reg_mem_qty
get_tev_mem = ida_dbg.get_tev_reg_mem
get_tev_mem_ea = ida_dbg.get_tev_reg_mem_ea
get_call_tev_callee = ida_dbg.get_call_tev_callee
get_ret_tev_return = ida_dbg.get_ret_tev_return
get_bpt_tev_ea = ida_dbg.get_bpt_tev_ea


#--------------------------------------------------------------------------
#                             C O L O R S
#--------------------------------------------------------------------------

def get_color(ea, what):
    """
    Get item color

    @param ea: address of the item
    @param what: type of the item (one of  CIC_* constants)

    @return: color code in RGB (hex 0xBBGGRR)
    """
    if what not in [ CIC_ITEM, CIC_FUNC, CIC_SEGM ]:
        raise ValueError("'what' must be one of CIC_ITEM, CIC_FUNC and CIC_SEGM")

    if what == CIC_ITEM:
        return ida_nalt.get_item_color(ea)

    if what == CIC_FUNC:
        func = ida_funcs.get_func(ea)
        if func:
            return func.color
        else:
            return DEFCOLOR

    if what == CIC_SEGM:
        seg = ida_segment.getseg(ea)
        if seg:
            return seg.color
        else:
            return DEFCOLOR

# color item codes:
CIC_ITEM = 1         # one instruction or data
CIC_FUNC = 2         # function
CIC_SEGM = 3         # segment

DEFCOLOR = 0xFFFFFFFF  # Default color


def set_color(ea, what, color):
    """
    Set item color

    @param ea: address of the item
    @param what: type of the item (one of CIC_* constants)
    @param color: new color code in RGB (hex 0xBBGGRR)

    @return: success (True or False)
    """
    if what not in [ CIC_ITEM, CIC_FUNC, CIC_SEGM ]:
        raise ValueError("'what' must be one of CIC_ITEM, CIC_FUNC and CIC_SEGM")

    if what == CIC_ITEM:
        return ida_nalt.set_item_color(ea, color)

    if what == CIC_FUNC:
        func = ida_funcs.get_func(ea)
        if func:
            func.color = color
            return bool(ida_funcs.update_func(func))
        else:
            return False

    if what == CIC_SEGM:
        seg = ida_segment.getseg(ea)
        if seg:
            seg.color = color
            return bool(seg.update())
        else:
            return False


#----------------------------------------------------------------------------
#                       A R M   S P E C I F I C
#----------------------------------------------------------------------------
def force_bl_jump(ea):
    """
    Some ARM compilers in Thumb mode use BL (branch-and-link)
    instead of B (branch) for long jumps, since BL has more range.
    By default, IDA tries to determine if BL is a jump or a call.
    You can override IDA's decision using commands in Edit/Other menu
    (Force BL call/Force BL jump) or the following two functions.

    Force BL instruction to be a jump

    @param ea: address of the BL instruction

    @return: 1-ok, 0-failed
    """
    return eval_idc("force_bl_jump(0x%x)"%ea)


def force_bl_call(ea):
    """
    Force BL instruction to be a call

    @param ea: address of the BL instruction

    @return: 1-ok, 0-failed
    """
    return eval_idc("force_bl_call(0x%x)"%ea)


#--------------------------------------------------------------------------
def set_flag(off, bit, value):
  v = get_inf_attr(off)
  if value:
    v = v | bit
  else:
    v = v & ~bit
  set_inf_attr(off, v)

# Convenience functions:
def here(): return get_screen_ea()
def is_mapped(ea): return (prev_addr(ea+1)==ea)

ARGV = []
"""The command line arguments passed to IDA via the -S switch."""

# END OF IDC COMPATIBILY CODE
