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

__X64__  = sys.maxsize > 0xFFFFFFFF
__EA64__ = ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL
WORDMASK = 0xFFFFFFFFFFFFFFFF if __EA64__ else 0xFFFFFFFF
class DeprecatedIDCError(Exception):
    """
    Exception for deprecated function calls
    """
    pass


def _IDC_GetAttr(obj, attrmap, attroffs):
    """
    Internal function to generically get object attributes
    Do not use unless you know what you are doing
    """
    if attroffs in attrmap and hasattr(obj, attrmap[attroffs][1]):
        return getattr(obj, attrmap[attroffs][1])
    else:
        errormsg = "attribute with offset %d not found, check the offset and report the problem" % attroffs
        raise KeyError, errormsg


def _IDC_SetAttr(obj, attrmap, attroffs, value):
    """
    Internal function to generically set object attributes
    Do not use unless you know what you are doing
    """
    # check for read-only atributes
    if attroffs in attrmap:
        if attrmap[attroffs][0]:
            raise KeyError, "attribute with offset %d is read-only" % attroffs
        elif hasattr(obj, attrmap[attroffs][1]):
            return setattr(obj, attrmap[attroffs][1], value)
    errormsg = "attribute with offset %d not found, check the offset and report the problem" % attroffs
    raise KeyError, errormsg


BADADDR         = ida_idaapi.BADADDR # Not allowed address value
BADSEL          = ida_idaapi.BADSEL  # Not allowed selector value/number
MAXADDR         = ida_ida.MAXADDR & WORDMASK
SIZE_MAX        = _ida_idaapi.SIZE_MAX
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
NEF_SEGS   = ida_loader.NEF_SEGS   # Create segments
NEF_RSCS   = ida_loader.NEF_RSCS   # Load resources
NEF_NAME   = ida_loader.NEF_NAME   # Rename entries
NEF_MAN    = ida_loader.NEF_MAN    # Manual load
NEF_FILL   = ida_loader.NEF_FILL   # Fill segment gaps
NEF_IMPS   = ida_loader.NEF_IMPS   # Create imports section
NEF_FIRST  = ida_loader.NEF_FIRST  # This is the first file loaded
NEF_CODE   = ida_loader.NEF_CODE   # for load_binary_file:
NEF_RELOAD = ida_loader.NEF_RELOAD # reload the file at the same place:
NEF_FLAT   = ida_loader.NEF_FLAT   # Autocreated FLAT group (PE)

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
def value_is_string(var): raise NotImplementedError, "this function is not needed in Python"
def value_is_long(var):   raise NotImplementedError, "this function is not needed in Python"
def value_is_float(var):  raise NotImplementedError, "this function is not needed in Python"
def value_is_func(var):   raise NotImplementedError, "this function is not needed in Python"
def value_is_pvoid(var):  raise NotImplementedError, "this function is not needed in Python"
def value_is_int64(var):  raise NotImplementedError, "this function is not needed in Python"

def to_ea(seg, off):
    """
    Return value of expression: ((seg<<4) + off)
    """
    return (seg << 4) + off

def form(format, *args):
    raise DeprecatedIDCError, "form() is deprecated. Use python string operations instead."

def substr(s, x1, x2):
    raise DeprecatedIDCError, "substr() is deprecated. Use python string operations instead."

def strstr(s1, s2):
    raise DeprecatedIDCError, "strstr() is deprecated. Use python string operations instead."

def strlen(s):
    raise DeprecatedIDCError, "strlen() is deprecated. Use python string operations instead."

def xtol(s):
    raise DeprecatedIDCError, "xtol() is deprecated. Use python long() instead."

def atoa(ea):
    """
    Convert address value to a string
    Return address in the form 'seg000:1234'
    (the same as in line prefixes)

    @param ea: address to format
    """
    return ida_kernwin.ea2str(ea)

def ltoa(n, radix):
    raise DeprecatedIDCError, "ltoa() is deprecated. Use python string operations instead."

def atol(s):
    raise DeprecatedIDCError, "atol() is deprecated. Use python long() instead."


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

    mask = 2**(offset+nbits) - 2**offset
    tmp = value & mask

    if count > 0:
        for x in xrange(count):
            if (tmp >> (offset+nbits-1)) & 1:
                tmp = (tmp << 1) | (1 << offset)
            else:
                tmp = (tmp << 1)
    else:
        for x in xrange(-count):
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

def add_idc_hotkey(hotkey, idcfunc):
    """
    Add hotkey for IDC function

    @param hotkey: hotkey name ('a', "Alt-A", etc)
    @param idcfunc: IDC function name

    @return: None
    """
    return ida_kernwin.add_idc_hotkey(hotkey, idcfunc)


def del_idc_hotkey(hotkey):
    """
    Delete IDC function hotkey

    @param hotkey: hotkey code to delete
    """
    return ida_kernwin.del_idc_hotkey(hotkey)


def jumpto(ea):
    """
    Move cursor to the specifed linear address

    @param ea: linear address
    """
    return ida_kernwin.jumpto(ea)


def auto_wait():
    """
    Process all entries in the autoanalysis queue
    Wait for the end of autoanalysis

    @note:    This function will suspend execution of the calling script
            till the autoanalysis queue is empty.
    """
    return ida_auto.auto_wait()


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
            raise NotImplementedError, "eval_idc() supports only expressions returning strings or longs"


def EVAL_FAILURE(code):
    """
    Check the result of eval_idc() for evaluation failures

    @param code: result of eval_idc()

    @return: True if there was an evaluation error
    """
    return type(code) == types.StringType and code.startswith("IDC_FAILURE: ")


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
    res = ida_loader.save_database_ex(idbname, flags & mask)
    return res

DBFL_BAK = ida_loader.DBFL_BAK # for compatiblity with older versions, eventually delete this

def validate_idb_names():
    """
    check consistency of IDB name records
    @return: number of inconsistent name records
    """
    return ida_nalt.validate_idb_names()

def qexit(code):
    """
    Stop execution of IDC program, close the database and exit to OS

    @param code: code to exit with.

    @return: -
    """
    ida_pro.qexit(code)


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


def load_and_run_plugin(name, arg):
    """
    Load and run a plugin

    @param name: The plugin name is a short plugin name without an extension
    @param arg: integer argument

    @return: 0 if could not load the plugin, 1 if ok
    """
    return ida_loader.load_and_run_plugin(name, arg)


def plan_to_apply_idasgn(name):
    """
    Load (plan to apply) a FLIRT signature file

    @param name:  signature name without path and extension

    @return: 0 if could not load the signature file, !=0 otherwise
    """
    return ida_funcs.plan_to_apply_idasgn(name)


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
            ida_funcs.del_func_cmt(func, False)
            ida_funcs.del_func_cmt(func, True)
            ida_funcs.del_func(ea)
        ida_bytes.del_hidden_range(ea)
        seg = ida_segment.getseg(ea)
        if seg:
            ida_segment.del_segment_cmt(seg, False)
            ida_segment.del_segment_cmt(seg, True)
            ida_segment.del_segm(ea, ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT)

        ea = ida_bytes.next_head(ea, ida_ida.cvar.inf.max_ea)


def create_insn(ea):
    """
    Create an instruction at the specified address

    @param ea: linear address

    @return: 0 - can not create an instruction (no such opcode, the instruction
    would overlap with existing items, etc) otherwise returns length of the
    instruction in bytes
    """
    return ida_ua.create_insn(ea)


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

SN_CHECK      = ida_name.SN_CHECK
SN_NOCHECK    = ida_name.SN_NOCHECK  # Don't fail if the name contains invalid characters.
                                     # If this bit is clear, all invalid chars
                                     # (those !is_ident_cp()) will be replaced
                                     # by SUBSTCHAR (usually '_').
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

def set_cmt(ea, comment, rptble):
    """
    Set an indented regular comment of an item

    @param ea: linear address
    @param comment: comment string
    @param rptble: is repeatable?

    @return: None
    """
    return ida_bytes.set_cmt(ea, comment, rptble)


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


def create_data(ea, flags, size, tid):
    """
    Create a data item at the specified address

    @param ea: linear address
    @param flags: FF_BYTE..FF_PACKREAL
    @param size: size of item in bytes
    @param tid: for FF_STRUCT the structure id

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_data(ea, flags, size, tid)


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


def create_custom_data(ea, size, dtid, fid):
    """
    Convert the item at address to custom data.

    @param ea: linear address.
    @param size: custom data size in bytes.
    @param dtid: data type ID.
    @param fid: data format ID.

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_custdata(ea, size, dtid, fid)



def create_align(ea, count, align):
    """
    Convert the current item to an alignment directive

    @param ea: linear address
    @param count: number of bytes to convert
    @param align: 0 or 1..32
              if it is 0, the correct alignment will be calculated
              by the kernel

    @return: 1-ok, 0-failure
    """
    return ida_bytes.create_align(ea, count, align)


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
        offset = int(m.group(2), 0)
        frame = ida_frame.get_frame(func)

        if register == -1 or not frame:
            return 0

        offset += func.frsize
        member = ida_struct.get_member(frame, offset)

        if member:
            # Member already exists, rename it
            if ida_struct.set_member_name(frame, offset, name):
                return 1
            else:
                return 0
        else:
            # No member at the offset, create a new one
            if ida_struct.add_struc_member(frame,
										   name,
										   offset,
										   ida_bytes.byteflag(),
										   None, 1) == 0:
                return 1
            else:
                return 0
    else:
        # Location as simple register name
        return ida_frame.add_regvar(func, start, end, location, name, None)


def del_items(ea, flags=0, size=1):
    """
    Convert the current item to an explored item

    @param ea: linear address
    @param flags: combination of DELIT_* constants
    @param size: size of the range to undefine

    @return: None
    """
    return ida_bytes.del_items(ea, flags, size)


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

AP_ALLOWDUPS    = 0x00000001L     # use 'dup' construct
AP_SIGNED       = 0x00000002L     # treats numbers as signed
AP_INDEX        = 0x00000004L     # display array element indexes as comments
AP_ARRAY        = 0x00000008L     # reserved (this flag is not stored in database)
AP_IDXBASEMASK  = 0x000000F0L     # mask for number base of the indexes
AP_IDXDEC       = 0x00000000L     # display indexes in decimal
AP_IDXHEX       = 0x00000010L     # display indexes in hex
AP_IDXOCT       = 0x00000020L     # display indexes in octal
AP_IDXBIN       = 0x00000030L     # display indexes in binary

def op_bin(ea, n):
    """
    Convert an operand of the item (instruction or data) to a binary number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands

    @return: 1-ok, 0-failure

    @note: the data items use only the type of the first operand
    """
    return ida_bytes.op_bin(ea, n)


def op_oct(ea, n):
    """
    Convert an operand of the item (instruction or data) to an octal number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return ida_bytes.op_oct(ea, n)


def op_dec(ea, n):
    """
    Convert an operand of the item (instruction or data) to a decimal number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return ida_bytes.op_dec(ea, n)


def op_hex(ea, n):
    """
    Convert an operand of the item (instruction or data) to a hexadecimal number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return ida_bytes.op_hex(ea, n)


def op_chr(ea, n):
    """
    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return ida_bytes.op_chr(ea, n)


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


def op_offset(ea, n, reftype, target, base, tdelta):
    """
    Convert operand to a complex offset expression
    This is a more powerful version of op_plain_offset() function.
    It allows to explicitly specify the reference type (off8,off16, etc)
    and the expression target with a possible target delta.
    The complex expressions are represented by IDA in the following form:

    target + tdelta - base

    If the target is not present, then it will be calculated using

    target = operand_value - tdelta + base

    The target must be present for LOW.. and HIGH.. reference types

    @param ea: linear address of the instruction/data
    @param n: number of operand to convert (the same as in op_plain_offset)
    @param reftype: one of REF_... constants
    @param target: an explicitly specified expression target. if you don't
              want to specify it, use -1. Please note that LOW... and
              HIGH... reference type requre the target.
    @param base: the offset base (a linear address)
    @param tdelta: a displacement from the target which will be displayed
              in the expression.

    @return: success (boolean)
    """
    return ida_offset.op_offset(ea, n, reftype, target, base, tdelta)


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

def op_seg(ea, n):
    """
    Convert operand to a segment expression

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return ida_bytes.op_seg(ea, n)


def op_num(ea, n):
    """
    Convert operand to a number (with default number base, radix)

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return ida_bytes.op_num(ea, n)


def op_flt(ea, n):
    """
    Convert operand to a floating-point number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands

    @return: 1-ok, 0-failure
    """
    return ida_bytes.op_flt(ea, n)


def op_man(ea, n, opstr):
    """
    Specify operand represenation manually.

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param opstr: a string represenation of the operand

    @note: IDA will not check the specified operand, it will simply display
    it instead of the orginal representation of the operand.
    """
    return ida_bytes.set_forced_operand(ea, n, opstr)


def toggle_sign(ea, n):
    """
    Change sign of the operand

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return ida_bytes.toggle_sign(ea, n)


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


def op_enum(ea, n, enumid, serial):
    """
    Convert operand to a symbolic constant

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    @param enumid: id of enumeration type
    @param serial: serial number of the constant in the enumeration
             The serial numbers are used if there are more than
             one symbolic constant with the same value in the
             enumeration. In this case the first defined constant
             get the serial number 0, then second 1, etc.
             There could be 256 symbolic constants with the same
             value in the enumeration.
    """
    return ida_bytes.op_enum(ea, n, enumid, serial)


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
    return ida_bytes.op_stroff(ea, n, path.cast(), 1, delta)


def op_stkvar(ea, n):
    """
    Convert operand to a stack variable

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return ida_bytes.op_stkvar(ea, n)


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
    """
    Mark the location as "variable"

    @param ea: address to mark

    @return: None

    @note: All that IDA does is to mark the location as "variable".
    Nothing else, no additional analysis is performed.
    This function may disappear in the future.
    """
    ida_bytes.doVar(ea, 1)

# Every anterior/posterior line has its number.
# Anterior  lines have numbers from E_PREV
# Posterior lines have numbers from E_NEXT
E_PREV = ida_lines.E_PREV
E_NEXT = ida_lines.E_NEXT

def get_extra_cmt(ea, n):
    """
    Get extra comment line

    @param ea: linear address
    @param n: number of line (0..MAX_ITEM_LINES)
          MAX_ITEM_LINES is defined in IDA.CFG

    To get anterior  line #n use (E_PREV + n)
    To get posterior line #n use (E_NEXT + n)

    @return: extra comment line string
    """
    return ida_lines.get_extra_cmt(ea, n)


def update_extra_cmt(ea, n, line):
    """
    Set or update extra comment line

    @param ea: linear address
    @param n: number of additional line (0..MAX_ITEM_LINES)
    @param line: the line to display

    @return: None

    @note: IDA displays additional lines from number 0 up to the first unexisting
    additional line. So, if you specify additional line #150 and there is no
    additional line #149, your line will not be displayed.  MAX_ITEM_LINES is
    defined in IDA.CFG

    To set anterior  line #n use (E_PREV + n)
    To set posterior line #n use (E_NEXT + n)
    """
    ida_lines.update_extra_cmt(ea, n, line)


def del_extra_cmt(ea, n):
    """
    Delete an extra comment line

    @param ea: linear address
    @param n: number of anterior additional line (0..MAX_ITEM_LINES)

    @return: None

    To delete anterior  line #n use (E_PREV + n)
    To delete posterior line #n use (E_NEXT + n)
    """
    ida_lines.del_extra_cmt(ea, n)


def set_manual_insn(ea, insn):
    """
    Specify instruction represenation manually.

    @param ea: linear address
    @param insn: a string represenation of the operand

    @note: IDA will not check the specified instruction, it will simply
    display it instead of the orginal representation.
    """
    return ida_bytes.set_manual_insn(ea, insn)


def get_manual_insn(ea):
    """
    Get manual representation of instruction

    @param ea: linear address

    @note: This function returns value set by set_manual_insn earlier.
    """
    return ida_bytes.get_manual_insn(ea)


def patch_dbg_byte(ea,value):
    """
    Change a byte in the debugged process memory only

    @param ea: address
    @param value: new value of the byte

    @return: 1 if successful, 0 if not
    """
    return ida_dbg.put_dbg_byte(ea, value)


def patch_byte(ea, value):
    """
    Change value of a program byte
    If debugger was active then the debugged process memory will be patched too

    @param ea: linear address
    @param value: new value of the byte

    @return: 1 if the database has been modified,
             0 if either the debugger is running and the process' memory
               has value 'value' at address 'ea',
               or the debugger is not running, and the IDB
               has value 'value' at address 'ea already.
    """
    return ida_bytes.patch_byte(ea, value)


def patch_word(ea, value):
    """
    Change value of a program word (2 bytes)

    @param ea: linear address
    @param value: new value of the word

    @return: 1 if the database has been modified,
             0 if either the debugger is running and the process' memory
               has value 'value' at address 'ea',
               or the debugger is not running, and the IDB
               has value 'value' at address 'ea already.
    """
    return ida_bytes.patch_word(ea, value)


def patch_dword(ea, value):
    """
    Change value of a double word

    @param ea: linear address
    @param value: new value of the double word

    @return: 1 if the database has been modified,
             0 if either the debugger is running and the process' memory
               has value 'value' at address 'ea',
               or the debugger is not running, and the IDB
               has value 'value' at address 'ea already.
    """
    return ida_bytes.patch_dword(ea, value)


def patch_qword(ea, value):
    """
    Change value of a quad word

    @param ea: linear address
    @param value: new value of the quad word

    @return: 1 if the database has been modified,
             0 if either the debugger is running and the process' memory
               has value 'value' at address 'ea',
               or the debugger is not running, and the IDB
               has value 'value' at address 'ea already.
    """
    return ida_bytes.patch_qword(ea, value)


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
           register if IDA is not able to find the corrent value.
    """
    reg = ida_idp.str2reg(reg);
    if reg >= 0:
        return ida_segregs.split_sreg_range(ea, reg, value, tag)
    else:
        return False


def auto_mark_range(start, end, queuetype):
    """
    Plan to perform an action in the future.
    This function will put your request to a special autoanalysis queue.
    Later IDA will retrieve the request from the queue and process
    it. There are several autoanalysis queue types. IDA will process all
    queries from the first queue and then switch to the second queue, etc.
    """
    return ida_auto.auto_mark_range(start, end, queuetype)


def auto_unmark(start, end, queuetype):
    """
    Remove range of addresses from a queue.
    """
    return ida_auto.auto_unmark(start, end, queuetype)


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
                -1 if an error occured
                OFILE_EXE: 0-can't generate exe file, 1-ok
    """
    f = ida_diskio.fopenWT(path)

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


def get_root_filename():
    """
    Get input file name

    This function returns name of the file being disassembled
    """
    return ida_nalt.get_root_filename()


def get_input_file_path():
    """
    Get input file path

    This function returns the full path of the file being disassembled
    """
    return ida_nalt.get_input_file_path()


def set_root_filename(path):
    """
    Set input file name
    This function updates the file name that is stored in the database
    It is used by the debugger and other parts of IDA
    Use it when the database is moved to another location or when you
    use remote debugging.

    @param path: new input file path
    """
    return ida_nalt.set_root_filename(path)


def get_idb_path():
    """
    Get IDB full path

    This function returns full path of the current IDB database
    """
    return ida_loader.get_path(ida_loader.PATH_TYPE_IDB)


def retrieve_input_file_md5():
    """
    Return the MD5 hash of the input binary file

    @return: MD5 string or None on error
    """
    return ida_nalt.retrieve_input_file_md5()


def get_full_flags(ea):
    """
    Get internal flags

    @param ea: linear address

    @return: 32-bit value of internal flags. See start of IDC.IDC file
        for explanations.
    """
    return ida_bytes.get_full_flags(ea)


def get_db_byte(ea):
    """
    Get one byte (8-bit) of the program at 'ea' from the database even if the debugger is active

    @param ea: linear address

    @return: byte value. If the byte has no value then 0xFF is returned.

    @note: If the current byte size is different from 8 bits, then the returned value may have more 1's.
    To check if a byte has a value, use is_loaded()
    """
    return ida_bytes.get_db_byte(ea)


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


def get_wide_byte(ea):
    """
    Get value of program byte

    @param ea: linear address

    @return: value of byte. If byte has no value then returns 0xFF
        If the current byte size is different from 8 bits, then the returned value
        might have more 1's.
        To check if a byte has a value, use is_loaded()
    """
    return ida_bytes.get_wide_byte(ea)


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


def read_dbg_memory(ea, size):
    """
    Read from debugger memory.

    @param ea: linear address
    @param size: size of data to read
    @return: data as a string. If failed, If failed, throws an exception

    Thread-safe function (may be called only from the main thread and debthread)
    """
    return ida_idd.dbg_read_memory(ea, size)


def write_dbg_memory(ea, data):
    """
    Write to debugger memory.

    @param ea: linear address
    @param data: string to write
    @return: number of written bytes (-1 - network/debugger error)

    Thread-safe function (may be called only from the main thread and debthread)
    """
    if not ida_idd.dbg_can_query():
        return -1
    elif len(data) > 0:
        return ida_idd.dbg_write_memory(ea, data)


def get_original_byte(ea):
    """
    Get original value of program byte

    @param ea: linear address

    @return: the original value of byte before any patch applied to it
    """
    return ida_bytes.get_original_byte(ea)


def get_wide_word(ea):
    """
    Get value of program word (2 bytes)

    @param ea: linear address

    @return: the value of the word. If word has no value then returns 0xFFFF
        If the current byte size is different from 8 bits, then the returned value
        might have more 1's.
    """
    return ida_bytes.get_wide_word(ea)


def get_wide_dword(ea):
    """
    Get value of program double word (4 bytes)

    @param ea: linear address

    @return: the value of the double word. If failed returns -1
    """
    return ida_bytes.get_wide_dword(ea)


def get_qword(ea):
    """
    Get value of program quadro word (8 bytes)

    @param ea: linear address

    @return: the value of the quadro word. If failed, returns -1
    """
    return ida_bytes.get_qword(ea)


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


def get_name_ea(fromaddr, name):
    """
    Get linear address of a name

    @param fromaddr: the referring address. Allows to retrieve local label
               addresses in functions. If a local name is not found,
               then address of a global name is returned.

    @param name: name of program byte

    @return: address of the name (BADADDR - no such name)

    @note: Dummy names (like byte_xxxx where xxxx are hex digits) are parsed by this
           function to obtain the address. The database is not consulted for them.
    """
    return ida_name.get_name_ea(fromaddr, name)


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


def get_screen_ea():
    """
    Get linear address of cursor
    """
    return ida_kernwin.get_screen_ea()


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

def next_addr(ea):
    """
    Get next address in the program

    @param ea: linear address

    @return: BADADDR - the specified address in the last used address
    """
    return ida_bytes.next_addr(ea)


def prev_addr(ea):
    """
    Get previous address in the program

    @param ea: linear address

    @return: BADADDR - the specified address in the first address
    """
    return ida_bytes.prev_addr(ea)


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


def next_not_tail(ea):
    """
    Get next not-tail address in the program
    This function searches for the next displayable address in the program.
    The tail bytes of instructions and data are not displayable.

    @param ea: linear address

    @return: BADADDR - no (more) not-tail addresses
    """
    return ida_bytes.next_not_tail(ea)


def prev_not_tail(ea):
    """
    Get previous not-tail address in the program
    This function searches for the previous displayable address in the program.
    The tail bytes of instructions and data are not displayable.

    @param ea: linear address

    @return: BADADDR - no (more) not-tail addresses
    """
    return ida_bytes.prev_not_tail(ea)


def get_item_head(ea):
    """
    Get starting address of the item (instruction or data)

    @param ea: linear address

    @return: the starting address of the item
             if the current address is unexplored, returns 'ea'
    """
    return ida_bytes.get_item_head(ea)


def get_item_end(ea):
    """
    Get address of the end of the item (instruction or data)

    @param ea: linear address

    @return: address past end of the item at 'ea'
    """
    return ida_bytes.get_item_end(ea)


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
GN_STRICT = ida_name.GN_STRICT       # fail if can not demangle
GN_SHORT = ida_name.GN_SHORT         # use short form of demangled name
GN_LONG = ida_name.GN_LONG           # use long form of demangled name
GN_LOCAL = ida_name.GN_LOCAL         # try to get local name first; if failed, get global
GN_ISRET = ida_name.GN_ISRET         # for dummy names: use retloc
GN_NOT_ISRET = ida_name.GN_NOT_ISRET # for dummy names: do not use retloc


def calc_gtn_flags(fromaddr, ea):
    """
    Calculate flags for get_name() function

    @param fromaddr: the referring address. May be BADADDR.
    @param ea: linear address

    @return:  success
    """
    return ida_name.calc_gtn_flags(fromaddr, ea)


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


def GetCommentEx(ea, repeatable):
    """
    Get regular indented comment

    @param ea: linear address

    @param repeatable: 1 to get the repeatable comment, 0 to get the normal comment

    @return: string or None if it fails
    """
    return ida_bytes.get_cmt(ea, repeatable)


def get_cmt(ea, repeatable):
    """
    Get regular indented comment

    @param ea: linear address

    @param repeatable: 1 to get the repeatable comment, 0 to get the normal comment

    @return: string or None if it fails
    """
    return GetCommentEx(ea, repeatable)


def get_forced_operand(ea, n):
    """
    Get manually entered operand string

    @param ea: linear address
    @param n: number of operand:
         0 - the first operand
         1 - the second operand

    @return: string or None if it fails
    """
    return ida_bytes.get_forced_operand(ea, n)

STRTYPE_C       = ida_nalt.STRTYPE_TERMCHR # C-style ASCII string
STRTYPE_PASCAL  = ida_nalt.STRTYPE_PASCAL  # Pascal-style ASCII string (length byte)
STRTYPE_LEN2    = ida_nalt.STRTYPE_LEN2    # Pascal-style, length is 2 bytes
STRTYPE_C_16    = ida_nalt.STRTYPE_C_16    # Unicode string
STRTYPE_LEN4    = ida_nalt.STRTYPE_LEN4    # Pascal-style, length is 4 bytes
STRTYPE_LEN2_16 = ida_nalt.STRTYPE_LEN2_16 # Pascal-style Unicode, length is 2 bytes
STRTYPE_LEN4_16 = ida_nalt.STRTYPE_LEN4_16 # Pascal-style Unicode, length is 4 bytes

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
def find_suspop   (ea, flag): return ida_search.find_suspop(ea, flag)
def find_code     (ea, flag): return ida_search.find_code(ea, flag)
def find_data     (ea, flag): return ida_search.find_data(ea, flag)
def find_unknown  (ea, flag): return ida_search.find_unknown(ea, flag)
def find_defined  (ea, flag): return ida_search.find_defined(ea, flag)
def find_imm      (ea, flag, value): return ida_search.find_imm(ea, flag, value)

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
    """
    @param ea: start address
    @param flag: combination of SEARCH_* flags
    @param y: number of text line at ea to start from (0..MAX_ITEM_LINES)
    @param x: coordinate in this line
    @param searchstr: search string

    @return: ea of result or BADADDR if not found
    """
    return ida_search.find_text(ea, y, x, searchstr, flag)


def find_binary(ea, flag, searchstr, radix=16):
    """
    @param ea: start address
    @param flag: combination of SEARCH_* flags
    @param searchstr: a string as a user enters it for Search Text in Core
    @param radix: radix of the numbers (default=16)

    @return: ea of result or BADADDR if not found

    @note: Example: "41 42" - find 2 bytes 41h,42h (radix is 16)
    """
    endea = flag & 1 and ida_ida.cvar.inf.max_ea or ida_ida.cvar.inf.min_ea
    return ida_search.find_binary(ea, endea, searchstr, radix, flag)


#----------------------------------------------------------------------------
#       G L O B A L   S E T T I N G S   M A N I P U L A T I O N
#----------------------------------------------------------------------------
def process_config_line(directive):
    """
    Parse one or more ida.cfg config directives
    @param directive: directives to process, for example: PACK_DATABASE=2

    @note: If the directives are erroneous, a fatal error will be generated.
           The settings are permanent: effective for the current session and the next ones
    """
    return eval_idc('process_config_line("%s")' % ida_kernwin.str2user(directive))


# The following functions allow you to set/get common parameters.
# Please note that not all parameters can be set directly.

def get_inf_attr(offset):
    """
    """
    val = _IDC_GetAttr(ida_ida.cvar.inf, _INFMAP, offset)
    if offset == INF_PROCNAME:
        # procName is a character array
        val = ida_idaapi.as_cstr(val)
    return val

def set_inf_attr(offset, value):
    if offset == INF_PROCNAME:
        raise NotImplementedError, "Please use ida_idp.set_processor_type() to change processor"
    # We really want to go through IDC's equivalent, because it might
    # have side-effects (i.e., send a notification, etc...)
    return eval_idc("set_inf_attr(%d, %d)" % (offset, value))


INF_VERSION    = 4            # short;   Version of database
INF_PROCNAME   = 6            # char[8]; Name of current processor
INF_GENFLAGS   = 22           # ushort;  General flags:
INFFL_AUTO     = 0x01         #              Autoanalysis is enabled?
INFFL_ALLASM   = 0x02         #              May use constructs not supported by
                              #              the target assembler
INFFL_LOADIDC  = 0x04         #              loading an idc file that contains database info
INFFL_NOUSER   = 0x08         #              do not store user info in the database
INFFL_READONLY = 0x10         #              (internal) temporary interdiction to modify the database
INFFL_CHKOPS   =  0x20        #              check manual operands?
INFFL_NMOPS    =  0x40        #              allow non-matched operands?
INFFL_GRAPH_VIEW= 0x80        #              currently using graph options (\dto{graph})
INF_LFLAGS     = 24           # uint32;  IDP-dependent flags
LFLG_PC_FPP    = 0x00000001   #              decode floating point processor
                              #              instructions?
LFLG_PC_FLAT   = 0x00000002   #              Flat model?
LFLG_64BIT     = 0x00000004   #              64-bit program?
LFLG_IS_DLL    = 0x00000008   #              is dynamic library?
LFLG_FLAT_OFF32= 0x00000010   #              treat REF_OFF32 as 32-bit offset for 16bit segments (otherwise try SEG16:OFF16)
LFLG_MSF       = 0x00000020   #              byte order: is MSB first?
LFLG_WIDE_HBF  = 0x00000040   #              bit order of wide bytes: high byte first?
LFLG_DBG_NOPATH= 0x00000080   #              do not store input full path
LFLG_SNAPSHOT  = 0x00000100   #              is memory snapshot?
LFLG_PACK      = 0x00000200   # pack the database?
LFLG_COMPRESS  = 0x00000400   # compress the database?
LFLG_KERNMODE  = 0x00000800   # is kernel mode binary?

INF_CHANGE_COUNTER= 28        # uint32; database change counter; keeps track of byte and segment modifications

INF_FILETYPE   = 32           # short;   type of input file (see ida.hpp)
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
INF_OSTYPE     = 34           # short;   FLIRT: OS type the program is for
OSTYPE_MSDOS= 0x0001
OSTYPE_WIN  = 0x0002
OSTYPE_OS2  = 0x0004
OSTYPE_NETW = 0x0008
INF_APPTYPE    = 36           # short;   FLIRT: Application type
APPT_CONSOLE= 0x0001          #              console
APPT_GRAPHIC= 0x0002          #              graphics
APPT_PROGRAM= 0x0004          #              EXE
APPT_LIBRARY= 0x0008          #              DLL
APPT_DRIVER = 0x0010          #              DRIVER
APPT_1THREAD= 0x0020          #              Singlethread
APPT_MTHREAD= 0x0040          #              Multithread
APPT_16BIT  = 0x0080          #              16 bit application
APPT_32BIT  = 0x0100          #              32 bit application
INF_ASMTYPE    = 38           # char;    target assembler number (0..n)
INF_SPECSEGS   = 39

INF_AF         = 40           # uint32;   Analysis flags:
AF_CODE        = 0x00000001   #              Trace execution flow
AF_MARKCODE    = 0x00000002   #              Mark typical code sequences as code
AF_JUMPTBL     = 0x00000004   #              Locate and create jump tables
AF_PURDAT      = 0x00000008   #              Control flow to data segment is ignored
AF_USED        = 0x00000010   #              Analyze and create all xrefs
AF_UNK         = 0x00000020   #              Delete instructions with no xrefs

AF_PROCPTR     = 0x00000040   #              Create function if data xref data->code32 exists
AF_PROC        = 0x00000080   #              Create functions if call is present
AF_FTAIL       = 0x00000100   #              Create function tails
AF_LVAR        = 0x00000200   #              Create stack variables
AF_STKARG      = 0x00000400   #              Propagate stack argument information
AF_REGARG      = 0x00000800   #              Propagate register argument information
AF_TRACE       = 0x00001000   #              Trace stack pointer
AF_VERSP       = 0x00002000   #              Perform full SP-analysis. (\ph{verify_sp})
AF_ANORET      = 0x00004000   #              Perform 'no-return' analysis
AF_MEMFUNC     = 0x00008000   #              Try to guess member function types
AF_TRFUNC      = 0x00010000   #              Truncate functions upon code deletion

AF_STRLIT      = 0x00020000   #              Create string literal if data xref exists
AF_CHKUNI      = 0x00040000   #              Check for unicode strings
AF_FIXUP       = 0x00080000   #              Create offsets and segments using fixup info
AF_DREFOFF     = 0x00100000   #              Create offset if data xref to seg32 exists
AF_IMMOFF      = 0x00200000   #              Convert 32bit instruction operand to offset
AF_DATOFF      = 0x00400000   #              Automatically convert data to offsets

AF_FLIRT       = 0x00800000   #              Use flirt signatures
AF_SIGCMT      = 0x01000000   #              Append a signature name comment for recognized anonymous library functions
AF_SIGMLT      = 0x02000000   #              Allow recognition of several copies of the same function
AF_HFLIRT      = 0x04000000   #              Automatically hide library functions

AF_JFUNC       = 0x08000000   #              Rename jump functions as j_...
AF_NULLSUB     = 0x10000000   #              Rename empty functions as nullsub_...

AF_DODATA      = 0x20000000   #              Coagulate data segs at the final pass
AF_DOCODE      = 0x40000000   #              Coagulate code segs at the final pass
AF_FINAL       = 0x80000000   #              Final pass of analysis

INF_AF2        = 44           # uint32;  Analysis flags 2

AF2_DOEH       = 0x00000001   #              Handle EH information

INF_BASEADDR   = 48           # uval_t;  base paragraph of the program
INF_START_SS   = 52           # int32;   value of SS at the start
INF_START_CS   = 56           # int32;   value of CS at the start
INF_START_IP   = 60           # ea_t;    IP register value at the start of
                              #          program execution
INF_START_EA   = 64           # ea_t;    Linear address of program entry point
INF_START_SP   = 68           # ea_t;    SP register value at the start of
                              #          program execution
INF_MAIN       = 72           # ea_t;    address of main()
INF_MIN_EA     = 76           # ea_t;    The lowest address used
                              #          in the program
INF_MAX_EA     = 80           # ea_t;    The highest address used
                              #          in the program - 1
INF_OMIN_EA    = 84
INF_OMAX_EA    = 88
INF_LOW_OFF    = 92           # ea_t;    low limit of voids
INF_HIGH_OFF   = 96           # ea_t;    high limit of voids
INF_MAXREF     = 100          # uval_t;  max xref depth
INF_START_PRIVRANGE     = 104 # uval_t; Range of addresses reserved for internal use.
INF_END_PRIVRANGE       = 108 # uval_t; Initially (MAXADDR, MAXADDR+0x100000)

INF_NETDELTA            = 112 # sval_t; Delta value to be added to all adresses for mapping to netnodes.
                              # Initially 0.
# CROSS REFERENCES
INF_XREFNUM    = 116          # char;    Number of references to generate
                              #          0 - xrefs won't be generated at all
INF_TYPE_XREFS = 117          # char;    Number of references to generate
                              #          in the struct & enum windows
                              #          0 - xrefs won't be generated at all
INF_REFCMTS    = 118          # uchar; number of comment lines to
                              #        generate for refs to ASCII
                              #        string or demangled name
                              #        0 - such comments won't be
                              #        generated at all
INF_XREFS      = 119          # char;    xrefs representation:
SW_SEGXRF      = 0x01         #              show segments in xrefs?
SW_XRFMRK      = 0x02         #              show xref type marks?
SW_XRFFNC      = 0x04         #              show function offsets?
SW_XRFVAL      = 0x08         #              show xref values? (otherwise-"...")

# NAMES
INF_MAX_AUTONAME_LEN = 120    # ushort;  max name length (without zero byte)
INF_NAMETYPE   = 122          # char;    dummy names represenation type
NM_REL_OFF     = 0
NM_PTR_OFF     = 1
NM_NAM_OFF     = 2
NM_REL_EA      = 3
NM_PTR_EA      = 4
NM_NAM_EA      = 5
NM_EA          = 6
NM_EA4         = 7
NM_EA8         = 8
NM_SHORT       = 9
NM_SERIAL      = 10
INF_SHORT_DN   = 124          # int32;   short form of demangled names
INF_LONG_DN    = 128          # int32;   long form of demangled names
                              #          see demangle.h for definitions
INF_DEMNAMES   = 132          # char;    display demangled names as:
DEMNAM_CMNT = 0               #              comments
DEMNAM_NAME = 1               #              regular names
DEMNAM_NONE = 2               #              don't display
DEMNAM_GCC3 = 4               #          assume gcc3 names (valid for gnu compiler)
DEMNAM_FIRST= 8               #          override type info
INF_LISTNAMES  = 133          # uchar;   What names should be included in the list?
LN_NORMAL      = 0x01         #              normal names
LN_PUBLIC      = 0x02         #              public names
LN_AUTO        = 0x04         #              autogenerated names
LN_WEAK        = 0x08         #              weak names

# DISASSEMBLY LISTING DETAILS
INF_INDENT     = 134          # char;    Indention for instructions
INF_COMMENT    = 135          # char;    Indention for comments
INF_MARGIN     = 136          # ushort;  max length of data lines
INF_LENXREF    = 138          # ushort;  max length of line with xrefs
INF_OUTFLAGS   = 140          # uint32;  output flags
OFLG_SHOW_VOID = 0x0002       #              Display void marks?
OFLG_SHOW_AUTO = 0x0004       #              Display autoanalysis indicator?
OFLG_GEN_NULL  = 0x0010       #              Generate empty lines?
OFLG_SHOW_PREF = 0x0020       #              Show line prefixes?
OFLG_PREF_SEG  = 0x0040       #              line prefixes with segment name?
OFLG_LZERO     = 0x0080       #              generate leading zeroes in numbers
OFLG_GEN_ORG   = 0x0100       #              Generate 'org' directives?
OFLG_GEN_ASSUME= 0x0200       #              Generate 'assume' directives?
OFLG_GEN_TRYBLKS = 0x0400     #              Generate try/catch directives?
INF_CMTFLAG    = 144          # char;    comments:
SW_RPTCMT      = 0x01         #              show repeatable comments?
SW_ALLCMT      = 0x02         #              comment all lines?
SW_NOCMT       = 0x04         #              no comments at all
SW_LINNUM      = 0x08         #              show source line numbers
INF_BORDER     = 145          # char;    Generate borders?
INF_BINPREF    = 146          # short;   # of instruction bytes to show
                              #          in line prefix
INF_PREFFLAG   = 148          # char;    line prefix type:
PREF_SEGADR    = 0x01         #              show segment addresses?
PREF_FNCOFF    = 0x02         #              show function offsets?
PREF_STACK     = 0x04         #              show stack pointer?

# STRING LITERALS
INF_STRLIT_FLAGS= 149         # uchar;   string literal flags
STRF_GEN       = 0x01         #              generate names?
STRF_AUTO      = 0x02         #              names have 'autogenerated' bit?
STRF_SERIAL    = 0x04         #              generate serial names?
STRF_COMMENT   = 0x10         #              generate auto comment for string references?
STRF_SAVECASE  = 0x20         #              preserve case of strings for identifiers
INF_STRLIT_BREAK= 150         # char;    string literal line break symbol
INF_STRLIT_ZEROES= 151        # char;    leading zeroes
INF_STRTYPE    = 152          # int32;   current ascii string type
                              #          is considered as several bytes:
                              #      low byte:
BPU_1B = 1
BPU_2B = 2
BPU_4B = 4

STRWIDTH_1B = 0
STRWIDTH_2B = 1
STRWIDTH_4B = 2
STRWIDTH_MASK = 0x03

STRLYT_TERMCHR = 0
STRLYT_PASCAL1 = 1
STRLYT_PASCAL2 = 2
STRLYT_PASCAL4 = 3
STRLYT_MASK = 0xFC
STRLYT_SHIFT = 2

STRTYPE_TERMCHR   = STRWIDTH_1B|STRLYT_TERMCHR<<STRLYT_SHIFT
STRTYPE_C         = STRTYPE_TERMCHR
STRTYPE_C16       = STRWIDTH_2B|STRLYT_TERMCHR<<STRLYT_SHIFT
STRTYPE_C_32      = STRWIDTH_4B|STRLYT_TERMCHR<<STRLYT_SHIFT
STRTYPE_PASCAL    = STRWIDTH_1B|STRLYT_PASCAL1<<STRLYT_SHIFT
STRTYPE_PASCAL_16 = STRWIDTH_2B|STRLYT_PASCAL1<<STRLYT_SHIFT
STRTYPE_LEN2      = STRWIDTH_1B|STRLYT_PASCAL2<<STRLYT_SHIFT
STRTYPE_LEN2_16   = STRWIDTH_2B|STRLYT_PASCAL2<<STRLYT_SHIFT
STRTYPE_LEN4      = STRWIDTH_1B|STRLYT_PASCAL4<<STRLYT_SHIFT
STRTYPE_LEN4_16   = STRWIDTH_2B|STRLYT_PASCAL4<<STRLYT_SHIFT

INF_STRLIT_PREF  = 156        # char[16];ASCII names prefix
INF_STRLIT_SERNUM= 172        # uint32;  serial number

# DATA ITEMS
INF_DATATYPES    = 176        # int32;   data types allowed in data carousel

# COMPILER
INF_COMPILER   = 180          # uchar;   compiler
COMP_MASK    = 0x0F           #              mask to apply to get the pure compiler id
COMP_UNK     = 0x00           # Unknown
COMP_MS      = 0x01           # Visual C++
COMP_BC      = 0x02           # Borland C++
COMP_WATCOM  = 0x03           # Watcom C++
COMP_GNU     = 0x06           # GNU C++
COMP_VISAGE  = 0x07           # Visual Age C++
COMP_BP      = 0x08           # Delphi
INF_MODEL       = 181         # uchar;  memory model & calling convention
INF_SIZEOF_INT  = 182         # uchar;  sizeof(int)
INF_SIZEOF_BOOL = 183         # uchar;  sizeof(bool)
INF_SIZEOF_ENUM = 184         # uchar;  sizeof(enum)
INF_SIZEOF_ALGN = 185         # uchar;  default alignment
INF_SIZEOF_SHORT= 186
INF_SIZEOF_LONG = 187
INF_SIZEOF_LLONG= 188
INF_SIZEOF_LDBL = 189         # uchar;  sizeof(long double)
INF_ABIBITS= 192              # uint32; ABI features
ABI_8ALIGN4      = 0x00000001 #   4 byte alignment for 8byte scalars (__int64/double) inside structures?
ABI_PACK_STKARGS = 0x00000002 #   do not align stack arguments to stack slots
ABI_BIGARG_ALIGN = 0x00000004 #   use natural type alignment for argument if the alignment exceeds native word size (e.g. __int64 argument should be 8byte aligned on some 32bit platforms)
ABI_STACK_LDBL   = 0x00000008 #   long double areuments are passed on stack
ABI_STACK_VARARGS= 0x00000010 #   varargs are always passed on stack (even when there are free registers)
ABI_HARD_FLOAT   = 0x00000020 #   use the floating-point register set
ABI_SET_BY_USER  = 0x00000040 #   compiler/abi were set by user flag
INF_APPCALL_OPTIONS= 196      # uint32; appcall options

# Redefine these offsets for 64-bit version
if __EA64__:
    INF_VERSION              =   4
    INF_PROCNAME             =   6
    INF_GENFLAGS             =   22
    INF_LFLAGS               =   24
    INF_CHANGE_COUNTER       =   28
    INF_FILETYPE             =   32
    INF_OSTYPE               =   34
    INF_APPTYPE              =   36
    INF_ASMTYPE              =   38
    INF_SPECSEGS             =   39
    INF_AF                   =   40
    INF_AF2                  =   44
    INF_BASEADDR             =   48
    INF_START_SS             =   56
    INF_START_CS             =   64
    INF_START_IP             =   72
    INF_START_EA             =   80
    INF_START_SP             =   88
    INF_MAIN                 =   96
    INF_MIN_EA               =  104
    INF_MAX_EA               =  112
    INF_OMIN_EA              =  120
    INF_OMAX_EA              =  128
    INF_LOW_OFF              =  136
    INF_HIGH_OFF             =  144
    INF_MAXREF               =  152
    INF_START_PRIVRANGE      =  160
    INF_END_PRIVRANGE        =  168
    INF_NETDELTA             =  176
    INF_XREFNUM              =  184
    INF_TYPE_XREFS           =  185
    INF_REFCMTS              =  186
    INF_XREFS                =  187
    INF_MAX_AUTONAME_LEN     =  188
    INF_NAMETYPE             =  190
    INF_SHORT_DN             =  192
    INF_LONG_DN              =  196
    INF_DEMNAMES             =  200
    INF_LISTNAMES            =  201
    INF_INDENT               =  202
    INF_COMMENT              =  203
    INF_MARGIN               =  204
    INF_LENXREF              =  206
    INF_OUTFLAGS             =  208
    INF_CMTFLAG              =  212
    INF_BORDER               =  213
    INF_BINPREF              =  214
    INF_PREFFLAG             =  216
    INF_STRLIT_FLAGS         =  217
    INF_STRLIT_BREAK         =  218
    INF_STRLIT_ZEROES        =  219
    INF_STRTYPE              =  220
    INF_STRLIT_PREF          =  224
    INF_STRLIT_SERNUM        =  240
    INF_DATATYPES            =  248
    INF_COMPILER             =  256
    INF_MODEL                =  257
    INF_SIZEOF_INT           =  258
    INF_SIZEOF_BOOL          =  259
    INF_SIZEOF_ENUM          =  260
    INF_SIZEOF_ALGN          =  261
    INF_SIZEOF_SHORT         =  262
    INF_SIZEOF_LONG          =  263
    INF_SIZEOF_LLONG         =  264
    INF_SIZEOF_LDBL          =  265
    INF_ABIBITS              =  268
    INF_APPCALL_OPTIONS      =  272

_INFMAP = {
INF_VERSION     : (False, 'version'),      # short;   Version of database
INF_PROCNAME    : (False, 'procname'),     # char[8]; Name of current processor
INF_LFLAGS      : (False, 'lflags'),       # char;    IDP-dependent flags
INF_DEMNAMES    : (False, 'demnames'),     # char;    display demangled names as:
INF_FILETYPE    : (False, 'filetype'),     # short;   type of input file (see ida.hpp)
INF_OSTYPE      : (False, 'ostype'),       # short;   FLIRT: OS type the program is for
INF_APPTYPE     : (False, 'apptype'),      # short;   FLIRT: Application type
INF_START_SP    : (False, 'start_sp'),     # long;    SP register value at the start of
INF_AF          : (False, 'af'),           # uint32;  Analysis flags
INF_AF2         : (False, 'af2'),          # uint32;  Analysis flags 2
INF_START_IP    : (False, 'start_ip'),     # long;    IP register value at the start of
INF_START_EA    : (False, 'start_ea'),     # long;    Linear address of program entry point
INF_MIN_EA      : (False, 'min_ea'),       # long;    The lowest address used
INF_MAX_EA      : (False, 'max_ea'),       # long;    The highest address used
INF_OMIN_EA     : (False, 'omin_ea'),
INF_OMAX_EA     : (False, 'omax_ea'),
INF_LOW_OFF     : (False, 'lowoff'),       # long;    low limit of voids
INF_HIGH_OFF    : (False, 'highoff'),      # long;    high limit of voids
INF_MAXREF      : (False, 'maxref'),       # long;    max xref depth
INF_STRLIT_BREAK: (False, 'strlit_break'), # char;    string literal line break symbol
INF_INDENT      : (False, 'indent'),       # char;    Indention for instructions
INF_COMMENT     : (False, 'comment'),      # char;    Indention for comments
INF_XREFNUM     : (False, 'xrefnum'),      # char;    Number of references to generate
INF_TYPE_XREFS  : (False, 'type_xrefnum'), # char;    Number of references to generate in the struct & enum windows
INF_SPECSEGS    : (False, 'specsegs'),
INF_BORDER      : (False, 's_limiter'),    # char;    Generate borders?
INF_GENFLAGS    : (False, 's_genflags'),   # ushort;  General flags:
INF_ASMTYPE     : (False, 'asmtype'),      # char;    target assembler number (0..n)
INF_BASEADDR    : (False, 'baseaddr'),     # long;    base paragraph of the program
INF_XREFS       : (False, 's_xrefflag'),   # char;    xrefs representation:
INF_BINPREF     : (False, 'bin_prefix_size'),
                                           # short;   # of instruction bytes to show
INF_CMTFLAG     : (False, 's_cmtflg'),     # char;    comments:
INF_NAMETYPE    : (False, 'nametype'),     # char;    dummy names represenation type
INF_PREFFLAG    : (False, 's_prefflag'),   # char;    line prefix type:
INF_STRLIT_FLAGS: (False, 'strlit_flags'),   # uchar;   string literal flags
INF_LISTNAMES   : (False, 'listnames'),    # uchar;   What names should be included in the list?
INF_STRLIT_PREF   : (False, 'strlit_pref'),   # char[16];ASCII names prefix
INF_STRLIT_SERNUM : (False, 'strlit_sernum'), # ulong;   serial number
INF_STRLIT_ZEROES : (False, 'strlit_zeroes'), # char;    leading zeroes
INF_START_SS    : (False, 'start_ss'),     # long;    value of SS at the start
INF_START_CS    : (False, 'start_cs'),     # long;    value of CS at the start
INF_MAIN        : (False, 'main'),         # long;    address of main()
INF_SHORT_DN    : (False, 'short_demnames'), # long;    short form of demangled names
INF_LONG_DN     : (False, 'long_demnames'), # long;    long form of demangled names
INF_DATATYPES   : (False, 'datatypes'),    # long;    data types allowed in data carousel
INF_STRTYPE     : (False, 'strtype'),      # long;    current ascii string type
INF_MAX_AUTONAME_LEN : (False, 'max_autoname_len'),      # ushort;  max name length (without zero byte)
INF_MARGIN      : (False, 'margin'),       # ushort;  max length of data lines
INF_LENXREF     : (False, 'lenxref'),      # ushort;  max length of line with xrefs
INF_OUTFLAGS    : (False, 'outflags'),     # uchar;   output flags
INF_COMPILER    : (False, 'cc'),           # uchar;   compiler

#INF_MODEL       = 184             # uchar;   memory model & calling convention
#INF_SIZEOF_INT  = 185             # uchar;   sizeof(int)
#INF_SIZEOF_BOOL = 186             # uchar;   sizeof(bool)
#INF_SIZEOF_ENUM = 187             # uchar;   sizeof(enum)
#INF_SIZEOF_ALGN = 188             # uchar;   default alignment
#INF_SIZEOF_SHORT = 189
#INF_SIZEOF_LONG  = 190
#INF_SIZEOF_LLONG = 191
INF_CHANGE_COUNTER  : (False, 'database_change_count'),
INF_APPCALL_OPTIONS : (False, 'appcall_options'),
INF_ABIBITS         : (False, 'abibits'),       # uint32; ABI features
INF_REFCMTS         : (False, 'refcmtnum'),
#INF_NETDELTA        : (False, 'netdelta'),
#INF_START_PRIVRANGE : (False, 'privrange.start_ea'),
#INF_END_PRIVRANGE   : (False, 'privrange.end_ea')
}


def set_processor_type (processor, level):
    """
    Change current processor

    @param processor: name of processor in short form.
                      run 'ida ?' to get list of allowed processor types
    @param level: the request leve:
       - SETPROC_IDB    set processor type for old idb
       - SETPROC_LOADER set processor type for new idb;
                        if the user has specified a compatible processor,
                        return success without changing it.
                        if failure, call loader_failure()
       - SETPROC_LOADER_NON_FATAL
                        the same as SETPROC_LOADER but non-fatal failures
       - SETPROC_USER   set user-specified processor
                        used for -p and manual processor change at later time
    """
    return ida_idp.set_processor_type(processor, level)

SETPROC_IDB              = ida_idp.SETPROC_IDB
SETPROC_LOADER           = ida_idp.SETPROC_LOADER
SETPROC_LOADER_NON_FATAL = ida_idp.SETPROC_LOADER_NON_FATAL
SETPROC_USER             = ida_idp.SETPROC_USER

def SetPrcsr(processor): return set_processor_type(processor, SETPROC_USER)


def set_target_assembler(asmidx):
    """
    Set target assembler
    @param asmidx: index of the target assembler in the array of
    assemblers for the current processor.

    @return: 1-ok, 0-failed
    """
    return ida_idp.set_target_assembler(asmidx)


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


def ask_seg(defval, prompt):
    """
    Ask the user to enter a segment value

    @param defval: the default value. This value
             will appear in the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered segment selector or BADSEL.
    """
    return ida_kernwin.ask_seg(defval, prompt)


def ask_yn(defval, prompt):
    """
    Ask the user a question and let him answer Yes/No/Cancel

    @param defval: the default answer. This answer will be selected if the user
            presses Enter. -1:cancel,0-no,1-ok
    @param prompt: the prompt to display in the dialog box

    @return: -1:cancel,0-no,1-ok
    """
    return ida_kernwin.ask_yn(defval, prompt)


def msg(message):
    """
    Display an UTF-8 string in the message window

    The result of the stringification of the arguments
    will be treated as an UTF-8 string.

    @param message: message to print (formatting is done in Python)

    This function can be used to debug IDC scripts
    """
    ida_kernwin.msg(message)


def warning(message):
    """
    Display a message in a message box

    @param message: message to print (formatting is done in Python)

    This function can be used to debug IDC scripts
    The user will be able to hide messages if they appear twice in a row on
    the screen
    """
    ida_kernwin.warning(message)


def error(format):
    """
    Display a fatal message in a message box and quit IDA

    @param format: message to print
    """
    ida_kernwin.error(format)


def set_ida_state(status):
    """
    Change IDA indicator.

    @param status: new status

    @return: the previous status.
    """
    return ida_auto.set_ida_state(status)


IDA_STATUS_READY    = 0 # READY     IDA is idle
IDA_STATUS_THINKING = 1 # THINKING  Analyzing but the user may press keys
IDA_STATUS_WAITING  = 2 # WAITING   Waiting for the user input
IDA_STATUS_WORK     = 3 # BUSY      IDA is busy


def refresh_idaview_anyway():
    """
    refresh_idaview_anyway all disassembly views
    """
    ida_kernwin.refresh_idaview_anyway()


def refresh_lists():
    """
    refresh_idaview_anyway all list views (names, functions, etc)
    """
    ida_kernwin.refresh_lists()


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


def set_selector(sel, value):
    """
    Set a selector value

    @param sel: the selector number
    @param value: value of selector

    @return: None

    @note: ida supports up to 4096 selectors.
            if 'sel' == 'val' then the selector is destroyed because
            it has no significance
    """
    return ida_segment.set_selector(sel, value)


def del_selector(sel):
    """
    Delete a selector

    @param sel: the selector number to delete

    @return: None

    @note: if the selector is found, it will be deleted
    """
    return ida_segment.del_selector(sel)


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

    return BADADDR


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
                                            # It can not hold more than ~1000 gaps.
ADDSEG_SPARSE  = ida_segment.ADDSEG_SPARSE  # Use sparse storage method for the new segment

def AddSeg(startea, endea, base, use32, align, comb):
    return add_segm_ex(startea, endea, base, use32, align, comb, ADDSEG_NOSREG)

def del_segm(ea, flags):
    """
    Delete a segment

    @param ea: any address in the segment
    @param flags: combination of SEGMOD_* flags

    @return: boolean success
    """
    return ida_segment.del_segm(ea, flags)

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


saAbs        = ida_segment.saAbs        # Absolute segment.
saRelByte    = ida_segment.saRelByte    # Relocatable, byte aligned.
saRelWord    = ida_segment.saRelWord    # Relocatable, word (2-byte, 16-bit) aligned.
saRelPara    = ida_segment.saRelPara    # Relocatable, paragraph (16-byte) aligned.
saRelPage    = ida_segment.saRelPage    # Relocatable, aligned on 256-byte boundary
                                        # (a "page" in the original Intel specification).
saRelDble    = ida_segment.saRelDble    # Relocatable, aligned on a double word
                                        # (4-byte) boundary. This value is used by
                                        # the PharLap OMF for the same alignment.
saRel4K      = ida_segment.saRel4K      # This value is used by the PharLap OMF for
                                        # page (4K) alignment. It is not supported
                                        # by LINK.
saGroup      = ida_segment.saGroup      # Segment group
saRel32Bytes = ida_segment.saRel32Bytes # 32 bytes
saRel64Bytes = ida_segment.saRel64Bytes # 64 bytes
saRelQword   = ida_segment.saRelQword   # 8 bytes


def set_segm_combination(segea, comb):
    """
    Change combination of the segment

    @param segea: any address in the segment
    @param comb: new combination of the segment (one of the sc... constants)

    @return: success (boolean)
    """
    return set_segm_attr(segea, SEGATTR_COMB, comb)


scPriv   = ida_segment.scPriv   # Private. Do not combine with any other program
                                # segment.
scPub    = ida_segment.scPub    # Public. Combine by appending at an offset that
                                # meets the alignment requirement.
scPub2   = ida_segment.scPub2   # As defined by Microsoft, same as C=2 (public).
scStack  = ida_segment.scStack  # Stack. Combine as for C=2. This combine type
                                # forces byte alignment.
scCommon = ida_segment.scCommon # Common. Combine by overlay using maximum size.
scPub3   = ida_segment.scPub3   # As defined by Microsoft, same as C=2 (public).


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
    Get segment by name

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


SEG_NORM   = ida_segment.SEG_NORM
SEG_XTRN   = ida_segment.SEG_XTRN   # * segment with 'extern' definitions
                                    #   no instructions are allowed
SEG_CODE   = ida_segment.SEG_CODE   # pure code segment
SEG_DATA   = ida_segment.SEG_DATA   # pure data segment
SEG_IMP    = ida_segment.SEG_IMP    # implementation segment
SEG_GRP    = ida_segment.SEG_GRP    # * group of segments
                                    #   no instructions are allowed
SEG_NULL   = ida_segment.SEG_NULL   # zero-length segment
SEG_UNDF   = ida_segment.SEG_UNDF   # undefined segment type
SEG_BSS    = ida_segment.SEG_BSS    # uninitialized segment
SEG_ABSSYM = ida_segment.SEG_ABSSYM # * segment with definitions of absolute symbols
                                    #   no instructions are allowed
SEG_COMM   = ida_segment.SEG_COMM   # * segment with communal definitions
                                    #   no instructions are allowed
SEG_IMEM   = ida_segment.SEG_IMEM   # internal processor memory & sfr (8051)


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

MOVE_SEGM_OK     =  0     # all ok
MOVE_SEGM_PARAM  = -1     # The specified segment does not exist
MOVE_SEGM_ROOM   = -2     # Not enough free room at the target address
MOVE_SEGM_IDP    = -3     # IDP module forbids moving the segment
MOVE_SEGM_CHUNK  = -4     # Too many chunks are defined, can't move
MOVE_SEGM_LOADER = -5     # The segment has been moved but the loader complained
MOVE_SEGM_ODD    = -6     # Can't move segments by an odd number of bytes


def rebase_program(delta, flags):
    """
    Rebase the whole program by 'delta' bytes

    @param delta: number of bytes to move the program
    @param flags: combination of MFS_... constants
                  it is recommended to use MSF_FIXONCE so that the loader takes
                  care of global variables it stored in the database

    @returns: error code MOVE_SEGM_...
    """
    return ida_segment.rebase_program(delta, flags)


def set_storage_type(start_ea, end_ea, stt):
    """
    Set storage type

    @param start_ea: starting address
    @param end_ea: ending address
    @param stt: new storage type, one of STT_VA and STT_MM

    @returns: 0 - ok, otherwise internal error code
    """
    return ida_bytes.change_storage_type(start_ea, end_ea, stt)


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
def add_cref(From, To, flowtype):
    """
    """
    return ida_xref.add_cref(From, To, flowtype)


def del_cref(From, To, undef):
    """
    Unmark exec flow 'from' 'to'

    @param undef: make 'To' undefined if no more references to it

    @returns: 1 - planned to be made undefined
    """
    return ida_xref.del_cref(From, To, undef)


# The following functions include the ordinary flows:
# (the ordinary flow references are returned first)
def get_first_cref_from(From):
    """
    Get first code xref from 'From'
    """
    return ida_xref.get_first_cref_from(From)


def get_next_cref_from(From, current):
    """
    Get next code xref from
    """
    return ida_xref.get_next_cref_from(From, current)


def get_first_cref_to(To):
    """
    Get first code xref to 'To'
    """
    return ida_xref.get_first_cref_to(To)


def get_next_cref_to(To, current):
    """
    Get next code xref to 'To'
    """
    return ida_xref.get_next_cref_to(To, current)


# The following functions don't take into account the ordinary flows:
def get_first_fcref_from(From):
    """
    Get first xref from 'From'
    """
    return ida_xref.get_first_fcref_from(From)


def get_next_fcref_from(From, current):
    """
    Get next xref from
    """
    return ida_xref.get_next_fcref_from(From, current)


def get_first_fcref_to(To):
    """
    Get first xref to 'To'
    """
    return ida_xref.get_first_fcref_to(To)


def get_next_fcref_to(To, current):
    """
    Get next xref to 'To'
    """
    return ida_xref.get_next_fcref_to(To, current)


# Data reference types (combine with XREF_USER!):
dr_O    = ida_xref.dr_O  # Offset
dr_W    = ida_xref.dr_W  # Write
dr_R    = ida_xref.dr_R  # Read
dr_T    = ida_xref.dr_T  # Text (names in manual operands)
dr_I    = ida_xref.dr_I  # Informational


def add_dref(From, To, drefType):
    """
    Create Data Ref
    """
    return ida_xref.add_dref(From, To, drefType)


def del_dref(From, To):
    """
    Unmark Data Ref
    """
    return ida_xref.del_dref(From, To)


def get_first_dref_from(From):
    """
    Get first data xref from 'From'
    """
    return ida_xref.get_first_dref_from(From)


def get_next_dref_from(From, current):
    """
    Get next data xref from 'From'
    """
    return ida_xref.get_next_dref_from(From, current)


def get_first_dref_to(To):
    """
    Get first data xref to 'To'
    """
    return ida_xref.get_first_dref_to(To)


def get_next_dref_to(To, current):
    """
    Get next data xref to 'To'
    """
    return ida_xref.get_next_dref_to(To, current)


def get_xref_type():
    """
    Return type of the last xref obtained by
    [RD]first/next[B0] functions.

    @return: constants fl_* or dr_*
    """
    raise DeprecatedIDCError, "use XrefsFrom() XrefsTo() from idautils instead."


#----------------------------------------------------------------------------
#                            F I L E   I / O
#----------------------------------------------------------------------------
def fopen(f, mode):
    raise DeprecatedIDCError, "fopen() deprecated. Use Python file objects instead."

def fclose(handle):
    raise DeprecatedIDCError, "fclose() deprecated. Use Python file objects instead."

def filelength(handle):
    raise DeprecatedIDCError, "filelength() deprecated. Use Python file objects instead."

def fseek(handle, offset, origin):
    raise DeprecatedIDCError, "fseek() deprecated. Use Python file objects instead."

def ftell(handle):
    raise DeprecatedIDCError, "ftell() deprecated. Use Python file objects instead."


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
    raise DeprecatedIDCError, "fgetc() deprecated. Use Python file objects instead."

def fputc(byte, handle):
    raise DeprecatedIDCError, "fputc() deprecated. Use Python file objects instead."

def fprintf(handle, format, *args):
    raise DeprecatedIDCError, "fprintf() deprecated. Use Python file objects instead."

def readshort(handle, mostfirst):
    raise DeprecatedIDCError, "readshort() deprecated. Use Python file objects instead."

def readlong(handle, mostfirst):
    raise DeprecatedIDCError, "readlong() deprecated. Use Python file objects instead."

def writeshort(handle, word, mostfirst):
    raise DeprecatedIDCError, "writeshort() deprecated. Use Python file objects instead."

def writelong(handle, dword, mostfirst):
    raise DeprecatedIDCError, "writelong() deprecated. Use Python file objects instead."

def readstr(handle):
    raise DeprecatedIDCError, "readstr() deprecated. Use Python file objects instead."

def writestr(handle, s):
    raise DeprecatedIDCError, "writestr() deprecated. Use Python file objects instead."

# ----------------------------------------------------------------------------
#                           F U N C T I O N S
# ----------------------------------------------------------------------------

def add_func(start, end = ida_idaapi.BADADDR):
    """
    Create a function

    @param start: function bounds
    @param end: function bounds

    If the function end address is BADADDR, then
    IDA will try to determine the function bounds
    automatically. IDA will define all necessary
    instructions to determine the function bounds.

    @return: !=0 - ok

    @note: an instruction should be present at the start address
    """
    return ida_funcs.add_func(start, end)


def del_func(ea):
    """
    Delete a function

    @param ea: any address belonging to the function

    @return: !=0 - ok
    """
    return ida_funcs.del_func(ea)


def set_func_end(ea, end):
    """
    Change function end address

    @param ea: any address belonging to the function
    @param end: new function end address

    @return: !=0 - ok
    """
    return ida_funcs.set_func_end(ea, end)


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
FUNCATTR_FRAME   = 12     # readonly: function frame id
FUNCATTR_FRSIZE  = 16     # readonly: size of local variables
FUNCATTR_FRREGS  = 20     # readonly: size of saved registers area
FUNCATTR_ARGSIZE = 24     # readonly: number of bytes purged from the stack
FUNCATTR_FPD     = 28     # frame pointer delta
FUNCATTR_COLOR   = 32     # function color code
FUNCATTR_OWNER   = 12     # readonly: chunk owner (valid only for tail chunks)
FUNCATTR_REFQTY  = 16     # readonly: number of chunk parents (valid only for tail chunks)

if __X64__:
    FUNCATTR_START   =  0
    FUNCATTR_END     =  4
    FUNCATTR_FLAGS   =  8
    FUNCATTR_FRAME   = 16
    FUNCATTR_FRSIZE  = 20
    FUNCATTR_FRREGS  = 24
    FUNCATTR_ARGSIZE = 28
    FUNCATTR_FPD     = 32
    FUNCATTR_COLOR   = 36
    FUNCATTR_OWNER   = 16
    FUNCATTR_REFQTY  = 20

# Redefining the constants for 64-bit
if __EA64__:
    FUNCATTR_START   =  0
    FUNCATTR_END     =  8
    FUNCATTR_FLAGS   = 16
    FUNCATTR_FRAME   = 20
    FUNCATTR_FRSIZE  = 28
    FUNCATTR_FRREGS  = 36
    FUNCATTR_ARGSIZE = 40
    FUNCATTR_FPD     = 48
    FUNCATTR_COLOR   = 56
    FUNCATTR_OWNER   = 20
    FUNCATTR_REFQTY  = 28
    if __X64__:
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


FUNC_NORET         = ida_funcs.FUNC_NORET         # function doesn't return
FUNC_FAR           = ida_funcs.FUNC_FAR           # far function
FUNC_LIB           = ida_funcs.FUNC_LIB           # library function
FUNC_STATIC        = ida_funcs.FUNC_STATICDEF     # static function
FUNC_FRAME         = ida_funcs.FUNC_FRAME         # function uses frame pointer (BP)
FUNC_USERFAR       = ida_funcs.FUNC_USERFAR       # user has specified far-ness
                                                  # of the function
FUNC_HIDDEN        = ida_funcs.FUNC_HIDDEN        # a hidden function
FUNC_THUNK         = ida_funcs.FUNC_THUNK         # thunk (jump) function
FUNC_BOTTOMBP      = ida_funcs.FUNC_BOTTOMBP      # BP points to the bottom of the stack frame
FUNC_NORET_PENDING = ida_funcs.FUNC_NORET_PENDING # Function 'non-return' analysis
                                                  # must be performed. This flag is
                                                  # verified upon func_does_return()
FUNC_SP_READY      = ida_funcs.FUNC_SP_READY      # SP-analysis has been performed
                                                  # If this flag is on, the stack
                                                  # change points should not be not
                                                  # modified anymore. Currently this
                                                  # analysis is performed only for PC
FUNC_PURGED_OK     = ida_funcs.FUNC_PURGED_OK     # 'argsize' field has been validated.
                                                  # If this bit is clear and 'argsize'
                                                  # is 0, then we do not known the real
                                                  # number of bytes removed from
                                                  # the stack. This bit is handled
                                                  # by the processor module.
FUNC_TAIL          = ida_funcs.FUNC_TAIL          # This is a function tail.
                                                  # Other bits must be clear
                                                  # (except FUNC_HIDDEN)


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

def add_user_stkpnt(ea, delta):
    """
    Add user-defined SP register change point.

    @param ea: linear address where SP changes
    @param delta: difference between old and new values of SP

    @return: 1-ok, 0-failed
    """
    return ida_frame.add_user_stkpnt(ea, delta);

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

def recalc_spd(cur_ea):
    """
    Recalculate SP delta for an instruction that stops execution.

    @param cur_ea: linear address of the current instruction
    @return: 1 - new stkpnt is added, 0 - nothing is changed
    """
    return ida_frame.recalc_spd(cur_ea)





# ----------------------------------------------------------------------------
#                        E N T R Y   P O I N T S
# ----------------------------------------------------------------------------

def get_entry_qty():
    """
    Retrieve number of entry points

    @returns: number of entry points
    """
    return ida_entry.get_entry_qty()


def add_entry(ordinal, ea, name, makecode):
    """
    Add entry point

    @param ordinal: entry point number
            if entry point doesn't have an ordinal
            number, 'ordinal' should be equal to 'ea'
    @param ea: address of the entry point
    @param name: name of the entry point. If null string,
            the entry point won't be renamed.
    @param makecode: if 1 then this entry point is a start
            of a function. Otherwise it denotes data bytes.

    @return: 0 - entry point with the specifed ordinal already exists
            1 - ok
    """
    return ida_entry.add_entry(ordinal, ea, name, makecode)


def get_entry_ordinal(index):
    """
    Retrieve entry point ordinal number

    @param index: 0..get_entry_qty()-1

    @return: 0 if entry point doesn't exist
            otherwise entry point ordinal
    """
    return ida_entry.get_entry_ordinal(index)


def get_entry(ordinal):
    """
    Retrieve entry point address

    @param ordinal: entry point number
        it is returned by GetEntryPointOrdinal()

    @return: BADADDR if entry point doesn't exist
            otherwise entry point address.
            If entry point address is equal to its ordinal
            number, then the entry point has no ordinal.
    """
    return ida_entry.get_entry(ordinal)


def get_entry_name(ordinal):
    """
    Retrieve entry point name

    @param ordinal: entry point number, ass returned by GetEntryPointOrdinal()

    @return: entry point name or None
    """
    return ida_entry.get_entry_name(ordinal)


def rename_entry(ordinal, name):
    """
    Rename entry point

    @param ordinal: entry point number
    @param name: new name

    @return: !=0 - ok
    """
    return ida_entry.rename_entry(ordinal, name)


# ----------------------------------------------------------------------------
#                              F I X U P S
# ----------------------------------------------------------------------------
def get_next_fixup_ea(ea):
    """
    Find next address with fixup information

    @param ea: current address

    @return: BADADDR - no more fixups otherwise returns the next
                address with fixup information
    """
    return ida_fixup.get_next_fixup_ea(ea)


def get_prev_fixup_ea(ea):
    """
    Find previous address with fixup information

    @param ea: current address

    @return: BADADDR - no more fixups otherwise returns the
                previous address with fixup information
    """
    return ida_fixup.get_prev_fixup_ea(ea)


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


def del_fixup(ea):
    """
    Delete fixup information

    @param ea: address to delete fixup information about

    @return: None
    """
    ida_fixup.del_fixup(ea)


#----------------------------------------------------------------------------
#                   M A R K E D   P O S I T I O N S
#----------------------------------------------------------------------------

def put_bookmark(ea, lnnum, x, y, slot, comment):
    """
    Mark position

    @param ea: address to mark
    @param lnnum: number of generated line for the 'ea'
    @param x: x coordinate of cursor
    @param y: y coordinate of cursor
    @param slot: slot number: 1..1024
                 if the specifed value is not within the
                 range, IDA will ask the user to select slot.
    @param comment: description of the mark. Should be not empty.

    @return: None
    """
    ida_idc.mark_position(ea, lnnum, x, y, slot, comment)


def get_bookmark(slot):
    """
    Get marked position

    @param slot: slot number: 1..1024 if the specifed value is <= 0
                 range, IDA will ask the user to select slot.

    @return: BADADDR - the slot doesn't contain a marked address
             otherwise returns the marked address
    """
    return ida_idc.get_marked_pos(slot)


def get_bookmark_desc(slot):
    """
    Get marked position comment

    @param slot: slot number: 1..1024

    @return: None if the slot doesn't contain a marked address
             otherwise returns the marked address comment
    """
    return ida_idc.get_mark_comment(slot)


# ----------------------------------------------------------------------------
#                          S T R U C T U R E S
# ----------------------------------------------------------------------------

def get_struc_qty():
    """
    Get number of defined structure types

    @return: number of structure types
    """
    return ida_struct.get_struc_qty()


def get_first_struc_idx():
    """
    Get index of first structure type

    @return:      BADADDR if no structure type is defined
                    index of first structure type.
                    Each structure type has an index and ID.
                    INDEX determines position of structure definition
                    in the list of structure definitions. Index 1
                    is listed first, after index 2 and so on.
                    The index of a structure type can be changed any
                    time, leading to movement of the structure definition
                    in the list of structure definitions.
                    ID uniquely denotes a structure type. A structure
                    gets a unique ID at the creation time and this ID
                    can't be changed. Even when the structure type gets
                    deleted, its ID won't be resued in the future.
    """
    return ida_struct.get_first_struc_idx()


def get_last_struc_idx():
    """
    Get index of last structure type

    @return:        BADADDR if no structure type is defined
                    index of last structure type.
                    See get_first_struc_idx() for the explanation of
                    structure indices and IDs.
    """
    return ida_struct.get_last_struc_idx()


def get_next_struc_idx(index):
    """
    Get index of next structure type

    @param index: current structure index

    @return:    BADADDR if no (more) structure type is defined
                index of the next structure type.
                See get_first_struc_idx() for the explanation of
                structure indices and IDs.
    """
    return ida_struct.get_next_struc_idx(index)


def get_prev_struc_idx(index):
    """
    Get index of previous structure type

    @param index: current structure index

    @return:    BADADDR if no (more) structure type is defined
                index of the presiouvs structure type.
                See get_first_struc_idx() for the explanation of
                structure indices and IDs.
    """
    return ida_struct.get_prev_struc_idx(index)


def get_struc_idx(sid):
    """
    Get structure index by structure ID

    @param sid: structure ID

    @return:    BADADDR if bad structure ID is passed
                otherwise returns structure index.
                See get_first_struc_idx() for the explanation of
                structure indices and IDs.
    """
    return ida_struct.get_struc_idx(sid)


def get_struc_by_idx(index):
    """
    Get structure ID by structure index

    @param index: structure index

    @return: BADADDR if bad structure index is passed otherwise returns structure ID.

    @note: See get_first_struc_idx() for the explanation of structure indices and IDs.
    """
    return ida_struct.get_struc_by_idx(index)


def get_struc_id(name):
    """
    Get structure ID by structure name

    @param name: structure type name

    @return:    BADADDR if bad structure type name is passed
                otherwise returns structure ID.
    """
    return ida_struct.get_struc_id(name)


def get_struc_name(sid):
    """
    Get structure type name

    @param sid: structure type ID

    @return:    None if bad structure type ID is passed
                otherwise returns structure type name.
    """
    return ida_struct.get_struc_name(sid)


def get_struc_cmt(sid, repeatable):
    """
    Get structure type comment

    @param sid: structure type ID
    @param repeatable: 1: get repeatable comment
                0: get regular comment

    @return: None if bad structure type ID is passed
                otherwise returns comment.
    """
    return ida_struct.get_struc_cmt(sid, repeatable)


def get_struc_size(sid):
    """
    Get size of a structure

    @param sid: structure type ID

    @return:    0 if bad structure type ID is passed
                otherwise returns size of structure in bytes.
    """
    return ida_struct.get_struc_size(sid)


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


def set_struc_name(sid, name):
    """
    Change structure name

    @param sid: structure type ID
    @param name: new name of the structure

    @return: != 0 - ok
    """
    return ida_struct.set_struc_name(sid, name)


def set_struc_cmt(sid, comment, repeatable):
    """
    Change structure comment

    @param sid: structure type ID
    @param comment: new comment of the structure
    @param repeatable: 1: change repeatable comment
                       0: change regular comment
    @return: != 0 - ok
    """
    return ida_struct.set_struc_cmt(sid, comment, repeatable)


def add_struc_member(sid, name, offset, flag, typeid, nbytes, target=-1, tdelta=0, reftype=REF_OFF32):
    """
    Add structure member

    @param sid: structure type ID
    @param name: name of the new member
    @param offset: offset of the new member
                   -1 means to add at the end of the structure
    @param flag: type of the new member. Should be one of
                 FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
    @param typeid: if isStruc(flag) then typeid specifies the structure id for the member
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
        return eval_idc('add_struc_member(%d, "%s", %d, %d, %d, %d, %d, %d, %d);' % (sid, ida_kernwin.str2user(name), offset, flag, typeid, nbytes,
                                                                               target, tdelta, reftype))
    else:
        return eval_idc('add_struc_member(%d, "%s", %d, %d, %d, %d);' % (sid, ida_kernwin.str2user(name), offset, flag, typeid, nbytes))


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
    @param typeid: if isStruc(flag) then typeid specifies the structure id for the member
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


def get_fchunk_referer(ea, idx):
    """
    Get a function chunk referer

    @param ea: any address in the chunk
    @param idx: referer index (0..get_fchunk_attr(FUNCATTR_REFQTY))

    @return: referer address or BADADDR
    """
    return ida_funcs.get_fchunk_referer(ea, idx)


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
        if not fci.next():
            break

    # Return the next chunk, if there is one
    if found and fci.next():
        return fci.chunk().start_ea
    else:
        return BADADDR


# ----------------------------------------------------------------------------
#                          E N U M S
# ----------------------------------------------------------------------------
def get_enum_qty():
    """
    Get number of enum types

    @return: number of enumerations
    """
    return ida_enum.get_enum_qty()


def getn_enum(idx):
    """
    Get ID of the specified enum by its serial number

    @param idx: number of enum (0..get_enum_qty()-1)

    @return: ID of enum or -1 if error
    """
    return ida_enum.getn_enum(idx)


def get_enum_idx(enum_id):
    """
    Get serial number of enum by its ID

    @param enum_id: ID of enum

    @return: (0..get_enum_qty()-1) or -1 if error
    """
    return ida_enum.get_enum_idx(enum_id)


def get_enum(name):
    """
    Get enum ID by the name of enum

    Arguments:
    name - name of enum

    returns:        ID of enum or -1 if no such enum exists
    """
    return ida_enum.get_enum(name)


def get_enum_name(enum_id):
    """
    Get name of enum

    @param enum_id: ID of enum

    @return: name of enum or empty string
    """
    return ida_enum.get_enum_name(enum_id)


def get_enum_cmt(enum_id, repeatable):
    """
    Get comment of enum

    @param enum_id: ID of enum
    @param repeatable: 0:get regular comment
                 1:get repeatable comment

    @return: comment of enum
    """
    return ida_enum.get_enum_cmt(enum_id, repeatable)


def get_enum_size(enum_id):
    """
    Get size of enum

    @param enum_id: ID of enum

    @return:  number of constants in the enum
              Returns 0 if enum_id is bad.
    """
    return ida_enum.get_enum_size(enum_id)


def get_enum_width(enum_id):
    """
    Get width of enum elements

    @param enum_id: ID of enum

    @return: size of enum elements in bytes
             (0 if enum_id is bad or the width is unknown).
    """
    return ida_enum.get_enum_width(enum_id)


def get_enum_flag(enum_id):
    """
    Get flag of enum

    @param enum_id: ID of enum

    @return: flags of enum. These flags determine representation
        of numeric constants (binary,octal,decimal,hex)
        in the enum definition. See start of this file for
        more information about flags.
        Returns 0 if enum_id is bad.
    """
    return ida_enum.get_enum_flag(enum_id)


def get_enum_member_by_name(name):
    """
    Get member of enum - a symbolic constant ID

    @param name: name of symbolic constant

    @return: ID of constant or -1
    """
    return ida_enum.get_enum_member_by_name(name)


def get_enum_member_value(const_id):
    """
    Get value of symbolic constant

    @param const_id: id of symbolic constant

    @return: value of constant or 0
    """
    return ida_enum.get_enum_member_value(const_id)


def get_enum_member_bmask(const_id):
    """
    Get bit mask of symbolic constant

    @param const_id: id of symbolic constant

    @return: bitmask of constant or 0
             ordinary enums have bitmask = -1
    """
    return ida_enum.get_enum_member_bmask(const_id)


def get_enum_member_enum(const_id):
    """
    Get id of enum by id of constant

    @param const_id: id of symbolic constant

    @return: id of enum the constant belongs to.
             -1 if const_id is bad.
    """
    return ida_enum.get_enum_member_enum(const_id)


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


def get_first_bmask(enum_id):
    """
    Get first bitmask in the enum (bitfield)

    @param enum_id: id of enum (bitfield)

    @return: the smallest bitmask of constant or -1
             no bitmasks are defined yet
             All bitmasks are sorted by their values
             as unsigned longs.
    """
    return ida_enum.get_first_bmask(enum_id)


def get_last_bmask(enum_id):
    """
    Get last bitmask in the enum (bitfield)

    @param enum_id: id of enum

    @return: the biggest bitmask or -1 no bitmasks are defined yet
             All bitmasks are sorted by their values as unsigned longs.
    """
    return ida_enum.get_last_bmask(enum_id)


def get_next_bmask(enum_id, value):
    """
    Get next bitmask in the enum (bitfield)

    @param enum_id: id of enum
    @param value: value of the current bitmask

    @return:  value of a bitmask with value higher than the specified
              value. -1 if no such bitmasks exist.
              All bitmasks are sorted by their values
              as unsigned longs.
    """
    return ida_enum.get_next_bmask(enum_id, value)


def get_prev_bmask(enum_id, value):
    """
    Get prev bitmask in the enum (bitfield)

    @param enum_id: id of enum
    @param value: value of the current bitmask

    @return: value of a bitmask with value lower than the specified
             value. -1 no such bitmasks exist.
             All bitmasks are sorted by their values as unsigned longs.
    """
    return ida_enum.get_prev_bmask(enum_id, value)


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


def del_enum(enum_id):
    """
    Delete enum type

    @param enum_id: id of enum

    @return: None
    """
    ida_enum.del_enum(enum_id)


def set_enum_idx(enum_id, idx):
    """
    Give another serial number to a enum

    @param enum_id: id of enum
    @param idx: new serial number.
        If another enum with the same serial number
        exists, then all enums with serial
        numbers >= the specified idx get their
        serial numbers incremented (in other words,
        the new enum is put in the middle of the list of enums).

        If idx >= get_enum_qty() then the enum is
        moved to the end of the list of enums.

    @return: comment string
    """
    return ida_enum.set_enum_idx(enum_id, idx)


def set_enum_name(enum_id, name):
    """
    Rename enum

    @param enum_id: id of enum
    @param name: new name of enum

    @return: 1-ok,0-failed
    """
    return ida_enum.set_enum_name(enum_id, name)


def set_enum_cmt(enum_id, cmt, repeatable):
    """
    Set comment of enum

    @param enum_id: id of enum
    @param cmt: new comment for the enum
    @param repeatable: is the comment repeatable?
        - 0:set regular comment
        - 1:set repeatable comment

    @return: 1-ok,0-failed
    """
    return ida_enum.set_enum_cmt(enum_id, cmt, repeatable)


def set_enum_flag(enum_id, flag):
    """
    Set flag of enum

    @param enum_id: id of enum
    @param flag: flags for representation of numeric constants
        in the definition of enum.

    @return: 1-ok,0-failed
    """
    return ida_enum.set_enum_flag(enum_id, flag)


def set_enum_bf(enum_id, flag):
    """
    Set bitfield property of enum

    @param enum_id: id of enum
    @param flag: flags
        - 1: convert to bitfield
        - 0: convert to ordinary enum

    @return: 1-ok,0-failed
    """
    return ida_enum.set_enum_bf(enum_id, flag)


def set_enum_width(enum_id, width):
    """
    Set width of enum elements

    @param enum_id: id of enum
    @param width: element width in bytes (0-unknown)

    @return: 1-ok, 0-failed
    """
    return ida_enum.set_enum_width(enum_id, width)


def is_bf(enum_id):
    """
    Is enum a bitfield?

    @param enum_id: id of enum

    @return: 1-yes, 0-no, ordinary enum
    """
    return ida_enum.is_bf(enum_id)


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


def set_enum_member_name(const_id, name):
    """
    Rename a member of enum - a symbolic constant

    @param const_id: id of const
    @param name: new name of constant

    @return: 1-ok, 0-failed
    """
    return ida_enum.set_enum_member_name(const_id, name)


def set_enum_member_cmt(const_id, cmt, repeatable):
    """
    Set a comment of a symbolic constant

    @param const_id: id of const
    @param cmt: new comment for the constant
    @param repeatable: is the comment repeatable?
        0: set regular comment
        1: set repeatable comment

    @return: 1-ok, 0-failed
    """
    return ida_enum.set_enum_member_cmt(const_id, cmt, repeatable)

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
            return __l2m1(node.altnext(idx, tag))
        elif tag == AR_STR:
            return __l2m1(node.supnext(idx, tag))
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
            return __l2m1(node.altprev(idx, tag))
        elif tag == AR_STR:
            return __l2m1(node.supprev(idx, tag))
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
def add_sourcefile(ea1, ea2, filename):
    """
    Mark a range of address as belonging to a source file
    An address range may belong only to one source file.
    A source file may be represented by several address ranges.

    @param ea1: linear address of start of the address range
    @param ea2: linear address of end of the address range
    @param filename: name of source file.

    @return: 1-ok, 0-failed.

    @note: IDA can keep information about source files used to create the program.
           Each source file is represented by a range of addresses.
           A source file may contains several address ranges.
    """
    return ida_lines.add_sourcefile(ea1, ea2, filename)


def get_sourcefile(ea):
    """
    Get name of source file occupying the given address

    @param ea: linear address

    @return: NULL - source file information is not found
             otherwise returns pointer to file name
    """
    return ida_lines.get_sourcefile(ea)


def del_sourcefile(ea):
    """
    Delete information about the source file

    @param ea: linear address belonging to the source file

    @return: NULL - source file information is not found
             otherwise returns pointer to file name
    """
    return ida_lines.del_sourcefile(ea)


def set_source_linnum(ea, lnnum):
    """
    Set source line number

    @param ea: linear address
    @param lnnum: number of line in the source file

    @return: None
    """
    ida_nalt.set_source_linnum(ea, lnnum)


def get_source_linnum(ea):
    """
    Get source line number

    @param ea: linear address

    @return: number of line in the source file or -1
    """
    return ida_nalt.get_source_linnum(ea)


def del_source_linnum(ea):
    """
    Delete information about source line number

    @param ea: linear address

    @return: None
    """
    ida_nalt.del_source_linnum(ea)


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
    @return: None on failure, or (type, fields, name) tuple.
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
    if isinstance(py_type, basestring) and len(py_type) == 0:
        pt = ("", "")
    else:
        if len(py_type) == 3:
          pt = py_type[1:]      # skip name component
        else:
          pt = py_type
    return ida_typeinf.apply_type(None, pt[0], pt[1], ea, flags)

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
    if newtype is not '':
        pt = parse_decl(newtype, 1) # silent
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


PT_FILE =   0x0001  # input if a file name (otherwise contains type declarations)
PT_SILENT = 0x0002  # silent mode
PT_PAKDEF = 0x0000  # default pack value
PT_PAK1 =   0x0010  # #pragma pack(1)
PT_PAK2 =   0x0020  # #pragma pack(2)
PT_PAK4 =   0x0030  # #pragma pack(4)
PT_PAK8 =   0x0040  # #pragma pack(8)
PT_PAK16 =  0x0050  # #pragma pack(16)
PT_HIGH  =  0x0080  # assume high level prototypes
                    # (with hidden args, etc)
PT_LOWER =  0x0100  # lower the function prototypes


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
    py_ordinals = map(lambda l : int(l), ordinals.split(","))
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
def add_hidden_range(start, end, description, header, footer, color):
    """
    Hide a range

    Hidden ranges - address ranges which can be replaced by their descriptions

    @param start:       range start
    @param end:         range end
    @param description: description to display if the range is collapsed
    @param header:      header lines to display if the range is expanded
    @param footer:      footer lines to display if the range is expanded
    @param color:       RGB color code (-1 means default color)

    @returns:    !=0 - ok
    """
    return ida_bytes.add_hidden_range(start, end, description, header, footer, color)


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


def del_hidden_range(ea):
    """
    Delete a hidden range

    @param ea: any address belonging to the hidden range
    @returns:  != 0 - ok
    """
    return ida_bytes.del_hidden_range(ea)


#--------------------------------------------------------------------------
#                   D E B U G G E R  I N T E R F A C E
#--------------------------------------------------------------------------
def load_debugger(dbgname, use_remote):
    """
    Load the debugger

    @param dbgname: debugger module name Examples: win32, linux, mac.
    @param use_remote: 0/1: use remote debugger or not

    @note: This function is needed only when running idc scripts from the command line.
           In other cases IDA loads the debugger module automatically.
    """
    return ida_dbg.load_debugger(dbgname, use_remote)


def start_process(path, args, sdir):
    """
    Launch the debugger

    @param path: path to the executable file.
    @param args: command line arguments
    @param sdir: initial directory for the process

    @return: -1-failed, 0-cancelled by the user, 1-ok

    @note: For all args: if empty, the default value from the database will be used
           See the important note to the step_into() function
    """
    return ida_dbg.start_process(path, args, sdir)


def exit_process():
    """
    Stop the debugger
    Kills the currently debugger process and returns to the disassembly mode

    @return: success
    """
    return ida_dbg.exit_process()


def suspend_process():
    """
    Suspend the running process
    Tries to suspend the process. If successful, the PROCESS_SUSPEND
    debug event will arrive (see wait_for_next_event)

    @return: success

    @note: To resume a suspended process use the wait_for_next_event function.
           See the important note to the step_into() function
    """
    return ida_dbg.suspend_process()


def get_processes():
    """
    Take a snapshot of running processes and return their description.

    @return: -1:network error, 0-failed, 1-ok
    """
    return ida_dbg.get_processes()


def attach_process(pid, event_id):
    """
    Attach the debugger to a running process

    @param pid: PID of the process to attach to. If NO_PROCESS, a dialog box
                will interactively ask the user for the process to attach to.
    @param event_id: reserved, must be -1

    @return:
             - -2: impossible to find a compatible process
             - -1: impossible to attach to the given process (process died, privilege
               needed, not supported by the debugger plugin, ...)
             - 0: the user cancelled the attaching to the process
             - 1: the debugger properly attached to the process
    @note: See the important note to the step_into() function
    """
    return ida_dbg.attach_process(pid, event_id)


def detach_process():
    """
    Detach the debugger from the debugged process.

    @return: success
    """
    return ida_dbg.detach_process()


def get_thread_qty():
    """
    Get number of threads.

    @return: number of threads
    """
    return ida_dbg.get_thread_qty()


def getn_thread(idx):
    """
    Get the ID of a thread

    @param idx: number of thread, is in range 0..get_thread_qty()-1

    @return: -1 if failure
    """
    return ida_dbg.getn_thread(idx)


def get_current_thread():
    """
    Get current thread ID

    @return: -1 if failure
    """
    return ida_dbg.get_current_thread()


def select_thread(tid):
    """
    Select the given thread as the current debugged thread.

    @param tid: ID of the thread to select

    @return: success

    @note: The process must be suspended to select a new thread.
    """
    return ida_dbg.select_thread(tid)


def suspend_thread(tid):
    """
    Suspend thread

    @param tid: thread id

    @return: -1:network error, 0-failed, 1-ok

    @note: Suspending a thread may deadlock the whole application if the suspended
           was owning some synchronization objects.
    """
    return ida_dbg.suspend_thread(tid)


def resume_thread(tid):
    """
    Resume thread

    @param tid: thread id

    @return: -1:network error, 0-failed, 1-ok
    """
    return ida_dbg.resume_thread(tid)


def _get_modules():
    """
    INTERNAL: Enumerate process modules
    """
    module = ida_idd.module_info_t()
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


def step_into():
    """
    Execute one instruction in the current thread.
    Other threads are kept suspended.

    @return: success

    @note: You must call wait_for_next_event() after this call
           in order to find out what happened. Normally you will
           get the STEP event but other events are possible (for example,
           an exception might occur or the process might exit).
           This remark applies to all execution control functions.
           The event codes depend on the issued command.
    """
    return ida_dbg.step_into()


def step_over():
    """
    Execute one instruction in the current thread,
    but without entering into functions
    Others threads keep suspended.
    See the important note to the step_into() function

    @return: success
    """
    return ida_dbg.step_over()


def run_to(ea):
    """
    Execute the process until the given address is reached.
    If no process is active, a new process is started.
    See the important note to the step_into() function

    @return: success
    """
    return ida_dbg.run_to(ea)


def step_until_ret():
    """
    Execute instructions in the current thread until
    a function return instruction is reached.
    Other threads are kept suspended.
    See the important note to the step_into() function

    @return: success
    """
    return ida_dbg.step_until_ret()


def wait_for_next_event(wfne, timeout):
    """
    Wait for the next event
    This function (optionally) resumes the process
    execution and wait for a debugger event until timeout

    @param wfne: combination of WFNE_... constants
    @param timeout: number of seconds to wait, -1-infinity

    @return: debugger event codes, see below
    """
    return ida_dbg.wait_for_next_event(wfne, timeout)


def resume_process():
    return wait_for_next_event(WFNE_CONT|WFNE_NOWAIT, 0)

def send_dbg_command(cmd):
    """Sends a command to the debugger module and returns the output string.
    An exception will be raised if the debugger is not running or the current debugger does not export
    the 'send_dbg_command' IDC command.
    """
    s = eval_idc('send_dbg_command("%s");' % ida_kernwin.str2user(cmd))
    if s.startswith("IDC_FAILURE"):
        raise Exception, "Debugger command is available only when the debugger is active!"
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
NOTASK         = -2         # process does not exist
DBG_ERROR      = -1         # error (e.g. network problems)
DBG_TIMEOUT    = 0          # timeout
PROCESS_START  = 0x00000001 # New process started
PROCESS_EXIT   = 0x00000002 # Process stopped
THREAD_START   = 0x00000004 # New thread started
THREAD_EXIT    = 0x00000008 # Thread stopped
BREAKPOINT     = 0x00000010 # Breakpoint reached
STEP           = 0x00000020 # One instruction executed
EXCEPTION      = 0x00000040 # Exception
LIBRARY_LOAD   = 0x00000080 # New library loaded
LIBRARY_UNLOAD = 0x00000100 # Library unloaded
INFORMATION    = 0x00000200 # User-defined information
SYSCALL        = 0x00000400 # Syscall (not used yet)
WINMESSAGE     = 0x00000800 # Window message (not used yet)
PROCESS_ATTACH = 0x00001000 # Attached to running process
PROCESS_DETACH = 0x00002000 # Detached from process
PROCESS_SUSPEND = 0x00004000 # Process has been suspended


def refresh_debugger_memory():
    """
    refresh_idaview_anyway debugger memory
    Upon this call IDA will forget all cached information
    about the debugged process. This includes the segmentation
    information and memory contents (register cache is managed
    automatically). Also, this function refreshes exported name
    from loaded DLLs.
    You must call this function before using the segmentation
    information, memory contents, or names of a non-suspended process.
    This is an expensive call.
    """
    return ida_dbg.refresh_debugger_memory()


def take_memory_snapshot(only_loader_segs):
    """
    Take memory snapshot of the debugged process

    @param only_loader_segs: 0-copy all segments to idb
                             1-copy only SFL_LOADER segments
    """
    return ida_segment.take_memory_snapshot(only_loader_segs)


def get_process_state():
    """
    Get debugged process state

    @return: one of the DBG_... constants (see below)
    """
    return ida_dbg.get_process_state()

DSTATE_SUSP            = -1 # process is suspended
DSTATE_NOTASK          =  0 # no process is currently debugged
DSTATE_RUN             =  1 # process is running
DSTATE_RUN_WAIT_ATTACH =  2 # process is running, waiting for process properly attached
DSTATE_RUN_WAIT_END    =  3 # process is running, but the user asked to kill/detach the process
                            # remark: in this case, most events are ignored

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
    return ev.eid


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


# For PROCESS_START, PROCESS_ATTACH, LIBRARY_LOAD events:

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

    @return: exit code for PROCESS_EXIT, THREAD_EXIT events
    """
    ev = ida_dbg.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.exit_code


def get_event_info():
    """
    Get debug event info

    @return: event info: for LIBRARY_UNLOAD (unloaded library name)
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


def set_debugger_options(opt):
    """
    Get/set debugger options

    @param opt: combination of DOPT_... constants

    @return: old options
    """
    return ida_dbg.set_debugger_options(opt)


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


def get_debugger_event_cond():
    """
    Return the debugger event condition
    """
    return ida_dbg.get_debugger_event_cond()


def set_debugger_event_cond(cond):
    """
    Set the debugger event condition
    """
    return ida_dbg.set_debugger_event_cond(cond)


def set_remote_debugger(hostname, password, portnum):
    """
    Set remote debugging options

    @param hostname: remote host name or address if empty, revert to local debugger
    @param password: password for the debugger server
    @param portnum: port number to connect (-1: don't change)

    @return: nothing
    """
    return ida_dbg.set_remote_debugger(hostname, password, portnum)


def define_exception(code, name, desc, flags):
    """
    Add exception handling information

    @param code: exception code
    @param name: exception name
    @param desc: exception description
    @param flags: exception flags (combination of EXC_...)

    @return: failure description or ""
    """
    return ida_dbg.define_exception(code, name, desc, flags)

EXC_BREAK  = 0x0001 # break on the exception
EXC_HANDLE = 0x0002 # should be handled by the debugger?


def get_reg_value(name):
    """
    Get register value

    @param name: the register name

    @note: The debugger should be running. otherwise the function fails
           the register name should be valid.
           It is not necessary to use this function to get register values
           because a register name in the script will do too.

    @return: register value (integer or floating point)
    """
    rv = ida_idd.regval_t()
    res = ida_dbg.get_reg_val(name, rv)
    assert res, "get_reg_val() failed, bogus register name ('%s') perhaps?" % name
    return rv.ival


def set_reg_value(value, name):
    """
    Set register value

    @param name: the register name
    @param value: new register value

    @note: The debugger should be running
           It is not necessary to use this function to set register values.
           A register name in the left side of an assignment will do too.
    """
    rv = ida_idd.regval_t()
    if type(value) == types.StringType:
        value = int(value, 16)
    elif type(value) != types.IntType and type(value) != types.LongType:
        print "set_reg_value: value must be integer!"
        return BADADDR

    if value < 0:
        #ival_set cannot handle negative numbers
        value &= 0xFFFFFFFF

    rv.ival = value
    return ida_dbg.set_reg_val(name, rv)


def get_bpt_qty():
    """
    Get number of breakpoints.

    @return: number of breakpoints
    """
    return ida_dbg.get_bpt_qty()


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
        if bptattr not in [ BPTATTR_SIZE, BPTATTR_TYPE, BPTATTR_FLAGS, BPTATTR_COUNT ]:
            return False
        if bptattr == BPTATTR_SIZE:
            bpt.size = value
        if bptattr == BPTATTR_TYPE:
            bpt.type = value
        if bptattr == BPTATTR_COUNT:
            bpt.pass_count = value
        if bptattr == BPTATTR_FLAGS:
            bpt.flags = value

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


def add_bpt(ea, size=0, bpttype=BPT_DEFAULT):
    """
    Add a new breakpoint

    @param ea: any address in the process memory space:
    @param size: size of the breakpoint (irrelevant for software breakpoints):
    @param bpttype: type of the breakpoint (one of BPT_... constants)

    @return: success

    @note: Only one breakpoint can exist at a given address.
    """
    return ida_dbg.add_bpt(ea, size, bpttype)


def del_bpt(ea):
    """
    Delete breakpoint

    @param ea: any address in the process memory space:

    @return: success
    """
    return ida_dbg.del_bpt(ea)


def enable_bpt(ea, enable):
    """
    Enable/disable breakpoint

    @param ea: any address in the process memory space

    @return: success

    @note: Disabled breakpoints are not written to the process memory
    """
    return ida_dbg.enable_bpt(ea, enable)


def check_bpt(ea):
    """
    Check a breakpoint

    @param ea: address in the process memory space

    @return: one of BPTCK_... constants
    """
    return ida_dbg.check_bpt(ea)

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


def get_step_trace_options():
    """
    Get step current tracing options

    @return: a combination of ST_... constants
    """
    return ida_dbg.get_step_trace_options()


def set_step_trace_options(options):
    """
    Set step current tracing options.
    @param options: combination of ST_... constants
    """
    return ida_dbg.set_step_trace_options(options)


ST_OVER_DEBUG_SEG = 0x01 # step tracing will be disabled when IP is in a debugger segment
ST_OVER_LIB_FUNC  = 0x02 # step tracing will be disabled when IP is in a library function
ST_ALREADY_LOGGED = 0x04 # step tracing will be disabled when IP is already logged
ST_SKIP_LOOPS     = 0x08 # step tracing will try to skip loops already recorded

def load_trace_file(filename):
    """
    Load a previously recorded binary trace file
    @param filename: trace file
    """
    return ida_dbg.load_trace_file(filename)

def save_trace_file(filename, description):
    """
    Save current trace to a binary trace file
    @param filename: trace file
    @param description: trace description
    """
    return ida_dbg.save_trace_file(filename, description)

def is_valid_trace_file(filename):
    """
    Check the given binary trace file
    @param filename: trace file
    """
    return ida_dbg.is_valid_trace_file(filename)

def diff_trace_file(filename):
    """
    Diff current trace buffer against given trace
    @param filename: trace file
    """
    return ida_dbg.diff_trace_file(filename)

def clear_trace(filename):
    """
    Clear the current trace buffer
    """
    return ida_dbg.clear_trace()

def get_trace_file_desc(filename):
    """
    Get the trace description of the given binary trace file
    @param filename: trace file
    """
    return ida_dbg.get_trace_file_desc(filename)

def set_trace_file_desc(filename, description):
    """
    Update the trace description of the given binary trace file
    @param filename: trace file
    @description: trace description
    """
    return ida_dbg.set_trace_file_desc(filename, description)

def get_tev_qty():
    """
    Return the total number of recorded events
    """
    return ida_dbg.get_tev_qty()

def get_tev_ea(tev):
    """
    Return the address of the specified event
    @param tev: event number
    """
    return ida_dbg.get_tev_ea(tev)

TEV_NONE  = 0 # no event
TEV_INSN  = 1 # an instruction trace
TEV_CALL  = 2 # a function call trace
TEV_RET   = 3 # a function return trace
TEV_BPT   = 4 # write, read/write, execution trace
TEV_MEM   = 5 # memory layout changed
TEV_EVENT = 6 # debug event

def get_tev_type(tev):
    """
    Return the type of the specified event (TEV_... constants)
    @param tev: event number
    """
    return ida_dbg.get_tev_type(tev)

def get_tev_tid(tev):
    """
    Return the thread id of the specified event
    @param tev: event number
    """
    return ida_dbg.get_tev_tid(tev)

def get_tev_reg(tev, reg):
    """
    Return the register value for the specified event
    @param tev: event number
    @param reg: register name (like EAX, RBX, ...)
    """
    return ida_dbg.get_tev_reg_val(tev, reg)

def get_tev_mem_qty(tev):
    """
    Return the number of blobs of memory recorded, for the specified event

    Note: this requires that the tracing options have been set to record pieces of memory for instruction events

    @param tev: event number
    """
    return ida_dbg.get_tev_reg_mem_qty(tev)

def get_tev_mem(tev, idx):
    """
    Return the blob of memory pointed to by 'index', for the specified event

    Note: this requires that the tracing options have been set to record pieces of memory for instruction events

    @param tev: event number
    @param idx: memory address index
    """
    return ida_dbg.get_tev_reg_mem(tev, idx)

def get_tev_mem_ea(tev, idx):
    """
    Return the address of the blob of memory pointed to by 'index' for the specified event

    Note: this requires that the tracing options have been set to record pieces of memory for instruction events

    @param tev: event number
    @param idx: memory address index
    """
    return ida_dbg.get_tev_reg_mem_ea(tev, idx)

def get_call_tev_callee(tev):
    """
    Return the address of the callee for the specified event
    @param tev: event number
    """
    return ida_dbg.get_call_tev_callee(tev)

def get_ret_tev_return(tev):
    """
    Return the return address for the specified event
    @param tev: event number
    """
    return ida_dbg.get_ret_tev_return(tev)

def get_bpt_tev_ea(tev):
    """
    Return the address of the specified TEV_BPT event
    @param tev: event number
    """
    return ida_dbg.get_bpt_tev_ea(tev)


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
        raise ValueError, "'what' must be one of CIC_ITEM, CIC_FUNC and CIC_SEGM"

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
        raise ValueError, "'what' must be one of CIC_ITEM, CIC_FUNC and CIC_SEGM"

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

#--------------------------------------------------------------------------
# Compatibility macros (auto-generated part. Comes first so
# that any re-definition below will override auto-generated part)
if sys.modules["__main__"].IDAPYTHON_COMPAT_695_API:

    # see header.i.in
    bc695redef = ida_idaapi.bc695redef

    # although many things have changed in the 'inf' structure,
    # let's still try and do the best we can here even though
    # some INF_* accessor enumerators don't exist anymore
    GetCharPrm=get_inf_attr
    GetLongPrm=get_inf_attr
    GetShortPrm=get_inf_attr
    SetCharPrm=set_inf_attr
    SetLongPrm=set_inf_attr
    SetShortPrm=set_inf_attr

    #--------------------------------------------------------------------------
    # Compatibility macros (non-auto-generated part)
    def CompileEx(inp, isfile): return compile_idc_file(inp) if isfile else compile_idc_text(inp)

    def WriteMap(filepath):
        return gen_file(OFILE_MAP, filepath, 0, BADADDR, GENFLG_MAPSEG|GENFLG_MAPNAME)

    def WriteTxt(filepath, ea1, ea2):
        return gen_file(OFILE_ASM, filepath, ea1, ea2, 0)

    def WriteExe(filepath):
        return gen_file(OFILE_EXE, filepath, 0, BADADDR, 0)

    UTP_STRUCT = ida_typeinf.UTP_STRUCT
    UTP_ENUM   = ida_typeinf.UTP_ENUM


    def begin_type_updating(utp):
        """
        Begin type updating. Use this function if you
        plan to call AddEnumConst or similar type modification functions
        many times or from inside a loop

        @param utp: one of UTP_xxxx consts
        @return: None
        """
        return ida_typeinf.begin_type_updating(utp)


    def end_type_updating(utp):
        """
        End type updating. Refreshes the type system
        at the end of type modification operations

        @param utp: one of ida_typeinf.UTP_xxxx consts
        @return: None
        """
        return ida_typeinf.end_type_updating(utp)

    from idc_bc695 import *

    SendDbgCommand=send_dbg_command

    def MakeFunction(start, end=ida_idaapi.BADADDR):
        return ida_funcs.add_func(start, end)

    ApplyType = apply_type
    GetManyBytes = get_bytes
    GetString = get_strlit_contents
    ClearTraceFile = clear_trace
    FindBinary = find_binary
    NextHead = next_head
    ParseTypes = parse_decls
    PrevHead = prev_head
    ProcessUiAction = process_ui_action
    SaveBase = save_database
    Eval = eval_idc
    def MakeStr(ea, endea):
        return create_strlit(ea, endea)

# Convenience functions:
def here(): return get_screen_ea()
def is_mapped(ea): return (prev_addr(ea+1)==ea)

ARGV = []
"""The command line arguments passed to IDA via the -S switch."""

# END OF IDC COMPATIBILY CODE
