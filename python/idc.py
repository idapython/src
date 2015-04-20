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
the byte value). These 32 bits are used in GetFlags/SetFlags functions.
You may freely examine these bits using GetFlags() but the use of the
SetFlags() function is strongly discouraged.

This file is subject to change without any notice.
Future versions of IDA may use other definitions.
"""
try:
    import idaapi
except ImportError:
    print "Could not import idaapi. Running in 'pydoc mode'."

import os
import re
import struct
import time
import types

__EA64__ = idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL
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


BADADDR         = idaapi.BADADDR # Not allowed address value
BADSEL          = idaapi.BADSEL  # Not allowed selector value/number
MAXADDR         = idaapi.MAXADDR & WORDMASK
SIZE_MAX        = idaapi.SIZE_MAX
#
#      Flag bit definitions (for GetFlags())
#
MS_VAL  = idaapi.MS_VAL             # Mask for byte value
FF_IVL  = idaapi.FF_IVL             # Byte has value ?

# Do flags contain byte value? (i.e. has the byte a value?)
# if not, the byte is uninitialized.

def hasValue(F):     return ((F & FF_IVL) != 0)     # any defined value?

def byteValue(F):
    """
    Get byte value from flags
    Get value of byte provided that the byte is initialized.
    This macro works ok only for 8-bit byte machines.
    """
    return (F & MS_VAL)


def isLoaded(ea):
    """Is the byte initialized?"""
    return hasValue(GetFlags(ea))  # any defined value?

MS_CLS   = idaapi.MS_CLS   # Mask for typing
FF_CODE  = idaapi.FF_CODE  # Code ?
FF_DATA  = idaapi.FF_DATA  # Data ?
FF_TAIL  = idaapi.FF_TAIL  # Tail ?
FF_UNK   = idaapi.FF_UNK   # Unknown ?

def isCode(F):       return ((F & MS_CLS) == FF_CODE) # is code byte?
def isData(F):       return ((F & MS_CLS) == FF_DATA) # is data byte?
def isTail(F):       return ((F & MS_CLS) == FF_TAIL) # is tail byte?
def isUnknown(F):    return ((F & MS_CLS) == FF_UNK)  # is unexplored byte?
def isHead(F):       return ((F & FF_DATA) != 0)      # is start of code/data?

#
#      Common bits
#
MS_COMM  = idaapi.MS_COMM  # Mask of common bits
FF_COMM  = idaapi.FF_COMM  # Has comment?
FF_REF   = idaapi.FF_REF   # has references?
FF_LINE  = idaapi.FF_LINE  # Has next or prev cmt lines ?
FF_NAME  = idaapi.FF_NAME  # Has user-defined name ?
FF_LABL  = idaapi.FF_LABL  # Has dummy name?
FF_FLOW  = idaapi.FF_FLOW  # Exec flow from prev instruction?
FF_VAR   = idaapi.FF_VAR   # Is byte variable ?
FF_ANYNAME = FF_LABL | FF_NAME

def isFlow(F):       return ((F & FF_FLOW) != 0)
def isVar(F):        return ((F & FF_VAR ) != 0)
def isExtra(F):      return ((F & FF_LINE) != 0)
def isRef(F):        return ((F & FF_REF)  != 0)
def hasName(F):      return ((F & FF_NAME) != 0)
def hasUserName(F):  return ((F & FF_ANYNAME) == FF_NAME)

MS_0TYPE  = idaapi.MS_0TYPE  # Mask for 1st arg typing
FF_0VOID  = idaapi.FF_0VOID  # Void (unknown)?
FF_0NUMH  = idaapi.FF_0NUMH  # Hexadecimal number?
FF_0NUMD  = idaapi.FF_0NUMD  # Decimal number?
FF_0CHAR  = idaapi.FF_0CHAR  # Char ('x')?
FF_0SEG   = idaapi.FF_0SEG   # Segment?
FF_0OFF   = idaapi.FF_0OFF   # Offset?
FF_0NUMB  = idaapi.FF_0NUMB  # Binary number?
FF_0NUMO  = idaapi.FF_0NUMO  # Octal number?
FF_0ENUM  = idaapi.FF_0ENUM  # Enumeration?
FF_0FOP   = idaapi.FF_0FOP   # Forced operand?
FF_0STRO  = idaapi.FF_0STRO  # Struct offset?
FF_0STK   = idaapi.FF_0STK   # Stack variable?

MS_1TYPE  = idaapi.MS_1TYPE  # Mask for 2nd arg typing
FF_1VOID  = idaapi.FF_1VOID  # Void (unknown)?
FF_1NUMH  = idaapi.FF_1NUMH  # Hexadecimal number?
FF_1NUMD  = idaapi.FF_1NUMD  # Decimal number?
FF_1CHAR  = idaapi.FF_1CHAR  # Char ('x')?
FF_1SEG   = idaapi.FF_1SEG   # Segment?
FF_1OFF   = idaapi.FF_1OFF   # Offset?
FF_1NUMB  = idaapi.FF_1NUMB  # Binary number?
FF_1NUMO  = idaapi.FF_1NUMO  # Octal number?
FF_1ENUM  = idaapi.FF_1ENUM  # Enumeration?
FF_1FOP   = idaapi.FF_1FOP   # Forced operand?
FF_1STRO  = idaapi.FF_1STRO  # Struct offset?
FF_1STK   = idaapi.FF_1STK   # Stack variable?

# The following macros answer questions like
#   'is the 1st (or 2nd) operand of instruction or data of the given type'?
# Please note that data items use only the 1st operand type (is...0)

def isDefArg0(F):    return ((F & MS_0TYPE) != FF_0VOID)
def isDefArg1(F):    return ((F & MS_1TYPE) != FF_1VOID)
def isDec0(F):       return ((F & MS_0TYPE) == FF_0NUMD)
def isDec1(F):       return ((F & MS_1TYPE) == FF_1NUMD)
def isHex0(F):       return ((F & MS_0TYPE) == FF_0NUMH)
def isHex1(F):       return ((F & MS_1TYPE) == FF_1NUMH)
def isOct0(F):       return ((F & MS_0TYPE) == FF_0NUMO)
def isOct1(F):       return ((F & MS_1TYPE) == FF_1NUMO)
def isBin0(F):       return ((F & MS_0TYPE) == FF_0NUMB)
def isBin1(F):       return ((F & MS_1TYPE) == FF_1NUMB)
def isOff0(F):       return ((F & MS_0TYPE) == FF_0OFF)
def isOff1(F):       return ((F & MS_1TYPE) == FF_1OFF)
def isChar0(F):      return ((F & MS_0TYPE) == FF_0CHAR)
def isChar1(F):      return ((F & MS_1TYPE) == FF_1CHAR)
def isSeg0(F):       return ((F & MS_0TYPE) == FF_0SEG)
def isSeg1(F):       return ((F & MS_1TYPE) == FF_1SEG)
def isEnum0(F):      return ((F & MS_0TYPE) == FF_0ENUM)
def isEnum1(F):      return ((F & MS_1TYPE) == FF_1ENUM)
def isFop0(F):       return ((F & MS_0TYPE) == FF_0FOP)
def isFop1(F):       return ((F & MS_1TYPE) == FF_1FOP)
def isStroff0(F):    return ((F & MS_0TYPE) == FF_0STRO)
def isStroff1(F):    return ((F & MS_1TYPE) == FF_1STRO)
def isStkvar0(F):    return ((F & MS_0TYPE) == FF_0STK)
def isStkvar1(F):    return ((F & MS_1TYPE) == FF_1STK)

#
#      Bits for DATA bytes
#
DT_TYPE  = idaapi.DT_TYPE & 0xFFFFFFFF  # Mask for DATA typing

FF_BYTE      = idaapi.FF_BYTE & 0xFFFFFFFF      # byte
FF_WORD      = idaapi.FF_WORD & 0xFFFFFFFF      # word
FF_DWRD      = idaapi.FF_DWRD & 0xFFFFFFFF      # dword
FF_QWRD      = idaapi.FF_QWRD & 0xFFFFFFFF      # qword
FF_TBYT      = idaapi.FF_TBYT & 0xFFFFFFFF      # tbyte
FF_ASCI      = idaapi.FF_ASCI & 0xFFFFFFFF      # ASCII ?
FF_STRU      = idaapi.FF_STRU & 0xFFFFFFFF      # Struct ?
FF_OWRD      = idaapi.FF_OWRD & 0xFFFFFFFF      # octaword (16 bytes)
FF_FLOAT     = idaapi.FF_FLOAT & 0xFFFFFFFF     # float
FF_DOUBLE    = idaapi.FF_DOUBLE & 0xFFFFFFFF    # double
FF_PACKREAL  = idaapi.FF_PACKREAL & 0xFFFFFFFF  # packed decimal real
FF_ALIGN     = idaapi.FF_ALIGN & 0xFFFFFFFF     # alignment directive

def isByte(F):     return (isData(F) and (F & DT_TYPE) == FF_BYTE)
def isWord(F):     return (isData(F) and (F & DT_TYPE) == FF_WORD)
def isDwrd(F):     return (isData(F) and (F & DT_TYPE) == FF_DWRD)
def isQwrd(F):     return (isData(F) and (F & DT_TYPE) == FF_QWRD)
def isOwrd(F):     return (isData(F) and (F & DT_TYPE) == FF_OWRD)
def isTbyt(F):     return (isData(F) and (F & DT_TYPE) == FF_TBYT)
def isFloat(F):    return (isData(F) and (F & DT_TYPE) == FF_FLOAT)
def isDouble(F):   return (isData(F) and (F & DT_TYPE) == FF_DOUBLE)
def isPackReal(F): return (isData(F) and (F & DT_TYPE) == FF_PACKREAL)
def isASCII(F):    return (isData(F) and (F & DT_TYPE) == FF_ASCI)
def isStruct(F):   return (isData(F) and (F & DT_TYPE) == FF_STRU)
def isAlign(F):    return (isData(F) and (F & DT_TYPE) == FF_ALIGN)

#
#      Bits for CODE bytes
#
MS_CODE  = idaapi.MS_CODE & 0xFFFFFFFF
FF_FUNC  = idaapi.FF_FUNC & 0xFFFFFFFF  # function start?
FF_IMMD  = idaapi.FF_IMMD & 0xFFFFFFFF  # Has Immediate value ?
FF_JUMP  = idaapi.FF_JUMP & 0xFFFFFFFF  # Has jump table

#
#      Loader flags
#
NEF_SEGS   = idaapi.NEF_SEGS   # Create segments
NEF_RSCS   = idaapi.NEF_RSCS   # Load resources
NEF_NAME   = idaapi.NEF_NAME   # Rename entries
NEF_MAN    = idaapi.NEF_MAN    # Manual load
NEF_FILL   = idaapi.NEF_FILL   # Fill segment gaps
NEF_IMPS   = idaapi.NEF_IMPS   # Create imports section
NEF_FIRST  = idaapi.NEF_FIRST  # This is the first file loaded
NEF_CODE   = idaapi.NEF_CODE   # for load_binary_file:
NEF_RELOAD = idaapi.NEF_RELOAD # reload the file at the same place:
NEF_FLAT   = idaapi.NEF_FLAT   # Autocreated FLAT group (PE)

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
def IsString(var): raise NotImplementedError, "this function is not needed in Python"
def IsLong(var):   raise NotImplementedError, "this function is not needed in Python"
def IsFloat(var):  raise NotImplementedError, "this function is not needed in Python"
def IsFunc(var):   raise NotImplementedError, "this function is not needed in Python"
def IsPvoid(var):  raise NotImplementedError, "this function is not needed in Python"
def IsInt64(var):  raise NotImplementedError, "this function is not needed in Python"

def MK_FP(seg, off):
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
    segname = SegName(ea)

    if segname == "":
        segname = "0"

    return "%s:%X" % (segname, ea)


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


# AddHotkey return codes
IDCHK_OK        =  0   # ok
IDCHK_ARG       = -1   # bad argument(s)
IDCHK_KEY       = -2   # bad hotkey name
IDCHK_MAX       = -3   # too many IDC hotkeys

def AddHotkey(hotkey, idcfunc):
    """
    Add hotkey for IDC function

    @param hotkey: hotkey name ('a', "Alt-A", etc)
    @param idcfunc: IDC function name

    @return: None
    """
    return idaapi.add_idc_hotkey(hotkey, idcfunc)


def DelHotkey(hotkey):
    """
    Delete IDC function hotkey

    @param hotkey: hotkey code to delete
    """
    return idaapi.del_idc_hotkey(hotkey)


def Jump(ea):
    """
    Move cursor to the specifed linear address

    @param ea: linear address
    """
    return idaapi.jumpto(ea)


def Wait():
    """
    Process all entries in the autoanalysis queue
    Wait for the end of autoanalysis

    @note:    This function will suspend execution of the calling script
            till the autoanalysis queue is empty.
    """
    return idaapi.autoWait()


def CompileEx(input, isfile):
    """
    Compile an IDC script

    The input should not contain functions that are
    currently executing - otherwise the behaviour of the replaced
    functions is undefined.

    @param input: if isfile != 0, then this is the name of file to compile
                  otherwise it holds the text to compile
    @param isfile: specify if 'input' holds a filename or the expression itself

    @return: 0 - ok, otherwise it returns an error message
    """
    if isfile:
        res = idaapi.Compile(input)
    else:
        res = idaapi.CompileLine(input)

    if res:
        return res
    else:
        return 0


def Eval(expr):
    """
    Evaluate an IDC expression

    @param expr: an expression

    @return: the expression value. If there are problems, the returned value will be "IDC_FAILURE: xxx"
             where xxx is the error description

    @note: Python implementation evaluates IDC only, while IDC can call other registered languages
    """
    rv = idaapi.idc_value_t()

    err = idaapi.calc_idc_expr(BADADDR, expr, rv)
    if err:
        return "IDC_FAILURE: "+err
    else:
        if rv.vtype == '\x01':   # VT_STR
            return rv.str
        elif rv.vtype == '\x02': # long
            return rv.num
        elif rv.vtype == '\x07': # VT_STR2
            return rv.c_str()
        else:
            raise NotImplementedError, "Eval() supports only expressions returning strings or longs"


def EVAL_FAILURE(code):
    """
    Check the result of Eval() for evaluation failures

    @param code: result of Eval()

    @return: True if there was an evaluation error
    """
    return type(code) == types.StringType and code.startswith("IDC_FAILURE: ")


def SaveBase(idbname, flags=0):
    """
    Save current database to the specified idb file

    @param idbname: name of the idb file. if empty, the current idb
                    file will be used.
    @param flags: combination of idaapi.DBFL_... bits or 0
    """
    if len(idbname) == 0:
        idbname = GetIdbPath()
    saveflags = idaapi.cvar.database_flags
    mask = idaapi.DBFL_KILL | idaapi.DBFL_COMP | idaapi.DBFL_BAK
    idaapi.cvar.database_flags &= ~mask
    idaapi.cvar.database_flags |= flags & mask
    res = idaapi.save_database(idbname, 0)
    idaapi.cvar.database_flags = saveflags
    return res

DBFL_BAK = idaapi.DBFL_BAK # for compatiblity with older versions, eventually delete this

def ValidateNames():
    """
    check consistency of IDB name records
    @return: number of inconsistent name records
    """
    return idaapi.validate_idb_names()

def Exit(code):
    """
    Stop execution of IDC program, close the database and exit to OS

    @param code: code to exit with.

    @return: -
    """
    idaapi.qexit(code)


def Exec(command):
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


def Sleep(milliseconds):
    """
    Sleep the specified number of milliseconds
    This function suspends IDA for the specified amount of time

    @param milliseconds: time to sleep
    """
    time.sleep(float(milliseconds)/1000)


def RunPlugin(name, arg):
    """
    Load and run a plugin

    @param name: The plugin name is a short plugin name without an extension
    @param arg: integer argument

    @return: 0 if could not load the plugin, 1 if ok
    """
    return idaapi.load_and_run_plugin(name, arg)


def ApplySig(name):
    """
    Load (plan to apply) a FLIRT signature file

    @param name:  signature name without path and extension

    @return: 0 if could not load the signature file, !=0 otherwise
    """
    return idaapi.plan_to_apply_idasgn(name)


#----------------------------------------------------------------------------
#      C H A N G E   P R O G R A M   R E P R E S E N T A T I O N
#----------------------------------------------------------------------------


def DeleteAll():
    """
    Delete all segments, instructions, comments, i.e. everything
    except values of bytes.
    """
    ea = idaapi.cvar.inf.minEA

    # Brute-force nuke all info from all the heads
    while ea != BADADDR and ea <= idaapi.cvar.inf.maxEA:
        idaapi.del_local_name(ea)
        idaapi.del_global_name(ea)
        func = idaapi.get_func(ea)
        if func:
            idaapi.del_func_cmt(func, False)
            idaapi.del_func_cmt(func, True)
            idaapi.del_func(ea)
        idaapi.del_hidden_area(ea)
        seg = idaapi.getseg(ea)
        if seg:
            idaapi.del_segment_cmt(seg, False)
            idaapi.del_segment_cmt(seg, True)
            idaapi.del_segm(ea, idaapi.SEGDEL_KEEP | idaapi.SEGDEL_SILENT)

        ea = idaapi.next_head(ea, idaapi.cvar.inf.maxEA)


def MakeCode(ea):
    """
    Create an instruction at the specified address

    @param ea: linear address

    @return: 0 - can not create an instruction (no such opcode, the instruction
    would overlap with existing items, etc) otherwise returns length of the
    instruction in bytes
    """
    return idaapi.create_insn(ea)


def AnalyzeArea(sEA, eEA):
    """
    Perform full analysis of the area

    @param sEA: starting linear address
    @param eEA: ending linear address (excluded)

    @return: 1-ok, 0-Ctrl-Break was pressed.
    """
    return idaapi.analyze_area(sEA, eEA)


def MakeNameEx(ea, name, flags):
    """
    Rename an address

    @param ea: linear address
    @param name: new name of address. If name == "", then delete old name
    @param flags: combination of SN_... constants

    @return: 1-ok, 0-failure
    """
    return idaapi.set_name(ea, name, flags)

SN_CHECK      = idaapi.SN_CHECK    # Fail if the name contains invalid
                                   # characters
                                   # If this bit is clear, all invalid chars
                                   # (those !is_ident_char()) will be replaced
                                   # by SubstChar (usually '_')
                                   # List of valid characters is defined in
                                   # ida.cfg
SN_NOCHECK    = idaapi.SN_NOCHECK  # Replace invalid chars with SubstChar
SN_PUBLIC     = idaapi.SN_PUBLIC   # if set, make name public
SN_NON_PUBLIC = idaapi.SN_NON_PUBLIC # if set, make name non-public
SN_WEAK       = idaapi.SN_WEAK     # if set, make name weak
SN_NON_WEAK   = idaapi.SN_NON_WEAK # if set, make name non-weak
SN_AUTO       = idaapi.SN_AUTO     # if set, make name autogenerated
SN_NON_AUTO   = idaapi.SN_NON_AUTO # if set, make name non-autogenerated
SN_NOLIST     = idaapi.SN_NOLIST   # if set, exclude name from the list
                                   # if not set, then include the name into
                                   # the list (however, if other bits are set,
                                   # the name might be immediately excluded
                                   # from the list)
SN_NOWARN     = idaapi.SN_NOWARN   # don't display a warning if failed
SN_LOCAL      = idaapi.SN_LOCAL    # create local name. a function should exist.
                                   # local names can't be public or weak.
                                   # also they are not included into the list
                                   # of names they can't have dummy prefixes

def MakeComm(ea, comment):
    """
    Set an indented regular comment of an item

    @param ea: linear address
    @param comment: comment string

    @return: None
    """
    return idaapi.set_cmt(ea, comment, 0)


def MakeRptCmt(ea, comment):
    """
    Set an indented repeatable comment of an item

    @param ea: linear address
    @param comment: comment string

    @return: None
    """
    return idaapi.set_cmt(ea, comment, 1)


def MakeArray(ea, nitems):
    """
    Create an array.

    @param ea: linear address
    @param nitems: size of array in items

    @note: This function will create an array of the items with the same type as
    the type of the item at 'ea'. If the byte at 'ea' is undefined, then
    this function will create an array of bytes.
    """
    flags = idaapi.getFlags(ea)

    if idaapi.isCode(flags) or idaapi.isTail(flags) or idaapi.isAlign(flags):
        return False

    if idaapi.isUnknown(flags):
        flags = idaapi.FF_BYTE

    if idaapi.isStruct(flags):
        ti = idaapi.opinfo_t()
        assert idaapi.get_opinfo(ea, 0, flags, ti), "get_opinfo() failed"
        itemsize = idaapi.get_data_elsize(ea, flags, ti)
        tid = ti.tid
    else:
        itemsize = idaapi.get_item_size(ea)
        tid = BADADDR

    return idaapi.do_data_ex(ea, flags, itemsize*nitems, tid)


def MakeStr(ea, endea):
    """
    Create a string.

    This function creates a string (the string type is determined by the
    value of GetLongPrm(INF_STRTYPE))

    @param ea: linear address
    @param endea: ending address of the string (excluded)
        if endea == BADADDR, then length of string will be calculated
        by the kernel

    @return: 1-ok, 0-failure

    @note: The type of an existing string is returned by GetStringType()
    """
    return idaapi.make_ascii_string(ea, 0 if endea == BADADDR else endea - ea, GetLongPrm(INF_STRTYPE))


def MakeData(ea, flags, size, tid):
    """
    Create a data item at the specified address

    @param ea: linear address
    @param flags: FF_BYTE..FF_PACKREAL
    @param size: size of item in bytes
    @param tid: for FF_STRU the structure id

    @return: 1-ok, 0-failure
    """
    return idaapi.do_data_ex(ea, flags, size, tid)


def MakeByte(ea):
    """
    Convert the current item to a byte

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doByte(ea, 1)


def MakeWord(ea):
    """
    Convert the current item to a word (2 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doWord(ea, 2)


def MakeDword(ea):
    """
    Convert the current item to a double word (4 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doDwrd(ea, 4)


def MakeQword(ea):
    """
    Convert the current item to a quadro word (8 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doQwrd(ea, 8)


def MakeOword(ea):
    """
    Convert the current item to an octa word (16 bytes/128 bits)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doOwrd(ea, 16)


def MakeYword(ea):
    """
    Convert the current item to a ymm word (32 bytes/256 bits)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doYwrd(ea, 32)


def MakeFloat(ea):
    """
    Convert the current item to a floating point (4 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doFloat(ea, 4)


def MakeDouble(ea):
    """
    Convert the current item to a double floating point (8 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doDouble(ea, 8)


def MakePackReal(ea):
    """
    Convert the current item to a packed real (10 or 12 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doPackReal(ea, idaapi.ph_get_tbyte_size())


def MakeTbyte(ea):
    """
    Convert the current item to a tbyte (10 or 12 bytes)

    @param ea: linear address

    @return: 1-ok, 0-failure
    """
    return idaapi.doTbyt(ea, idaapi.ph_get_tbyte_size())


def MakeStructEx(ea, size, strname):
    """
    Convert the current item to a structure instance

    @param ea: linear address
    @param size: structure size in bytes. -1 means that the size
        will be calculated automatically
    @param strname: name of a structure type

    @return: 1-ok, 0-failure
    """
    strid = idaapi.get_struc_id(strname)

    if size == -1:
        size = idaapi.get_struc_size(strid)

    return idaapi.doStruct(ea, size, strid)


def MakeCustomDataEx(ea, size, dtid, fid):
    """
    Convert the item at address to custom data.

    @param ea: linear address.
    @param size: custom data size in bytes.
    @param dtid: data type ID.
    @param fid: data format ID.

    @return: 1-ok, 0-failure
    """
    return idaapi.doCustomData(ea, size, dtid, fid)



def MakeAlign(ea, count, align):
    """
    Convert the current item to an alignment directive

    @param ea: linear address
    @param count: number of bytes to convert
    @param align: 0 or 1..32
              if it is 0, the correct alignment will be calculated
              by the kernel

    @return: 1-ok, 0-failure
    """
    return idaapi.doAlign(ea, count, align)


def MakeLocal(start, end, location, name):
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
    func = idaapi.get_func(start)

    if not func:
        return 0

    # Find out if location is in the [bp+xx] form
    r = re.compile("\[([a-z]+)([-+][0-9a-fx]+)", re.IGNORECASE)
    m = r.match(location)

    if m:
        # Location in the form of [bp+xx]
        register = idaapi.str2reg(m.group(1))
        offset = int(m.group(2), 0)
        frame = idaapi.get_frame(func)

        if register == -1 or not frame:
            return 0

        offset += func.frsize
        member = idaapi.get_member(frame, offset)

        if member:
            # Member already exists, rename it
            if idaapi.set_member_name(frame, offset, name):
                return 1
            else:
                return 0
        else:
            # No member at the offset, create a new one
            if idaapi.add_struc_member(frame,
                                       name,
                                       offset,
                                       idaapi.byteflag(),
                                       None, 1) == 0:
                return 1
            else:
                return 0
    else:
        # Location as simple register name
        return idaapi.add_regvar(func, start, end, location, name, None)


def MakeUnkn(ea, flags):
    """
    Convert the current item to an explored item

    @param ea: linear address
    @param flags: combination of DOUNK_* constants

    @return: None
    """
    return idaapi.do_unknown(ea, flags)


def MakeUnknown(ea, size, flags):
    """
    Convert the current item to an explored item

    @param ea: linear address
    @param size: size of the range to undefine (for MakeUnknown)
    @param flags: combination of DOUNK_* constants

    @return: None
    """
    return idaapi.do_unknown_range(ea, size, flags)


DOUNK_SIMPLE   = idaapi.DOUNK_SIMPLE   # simply undefine the specified item
DOUNK_EXPAND   = idaapi.DOUNK_EXPAND   # propogate undefined items, for example
                                       # if removing an instruction removes all
                                       # references to the next instruction, then
                                       # plan to convert to unexplored the next
                                       # instruction too.
DOUNK_DELNAMES = idaapi.DOUNK_DELNAMES # delete any names at the specified address(es)


def SetArrayFormat(ea, flags, litems, align):
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
    return Eval("SetArrayFormat(0x%X, 0x%X, %d, %d)"%(ea, flags, litems, align))

AP_ALLOWDUPS    = 0x00000001L     # use 'dup' construct
AP_SIGNED       = 0x00000002L     # treats numbers as signed
AP_INDEX        = 0x00000004L     # display array element indexes as comments
AP_ARRAY        = 0x00000008L     # reserved (this flag is not stored in database)
AP_IDXBASEMASK  = 0x000000F0L     # mask for number base of the indexes
AP_IDXDEC       = 0x00000000L     # display indexes in decimal
AP_IDXHEX       = 0x00000010L     # display indexes in hex
AP_IDXOCT       = 0x00000020L     # display indexes in octal
AP_IDXBIN       = 0x00000030L     # display indexes in binary

def OpBinary(ea, n):
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
    return idaapi.op_bin(ea, n)


def OpOctal(ea, n):
    """
    Convert an operand of the item (instruction or data) to an octal number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_oct(ea, n)


def OpDecimal(ea, n):
    """
    Convert an operand of the item (instruction or data) to a decimal number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_dec(ea, n)


def OpHex(ea, n):
    """
    Convert an operand of the item (instruction or data) to a hexadecimal number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_hex(ea, n)


def OpChr(ea, n):
    """
    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_chr(ea, n)


def OpOff(ea, n, base):
    """
    Convert operand to an offset
    (for the explanations of 'ea' and 'n' please see OpBinary())

    Example:
    ========

        seg000:2000 dw      1234h

        and there is a segment at paragraph 0x1000 and there is a data item
        within the segment at 0x1234:

        seg000:1234 MyString        db 'Hello, world!',0

        Then you need to specify a linear address of the segment base to
        create a proper offset:

        OpOff(["seg000",0x2000],0,0x10000);

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
    return idaapi.set_offset(ea, n, base)


OPND_OUTER = idaapi.OPND_OUTER # outer offset base


def OpOffEx(ea, n, reftype, target, base, tdelta):
    """
    Convert operand to a complex offset expression
    This is a more powerful version of OpOff() function.
    It allows to explicitly specify the reference type (off8,off16, etc)
    and the expression target with a possible target delta.
    The complex expressions are represented by IDA in the following form:

    target + tdelta - base

    If the target is not present, then it will be calculated using

    target = operand_value - tdelta + base

    The target must be present for LOW.. and HIGH.. reference types

    @param ea: linear address of the instruction/data
    @param n: number of operand to convert (the same as in OpOff)
    @param reftype: one of REF_... constants
    @param target: an explicitly specified expression target. if you don't
              want to specify it, use -1. Please note that LOW... and
              HIGH... reference type requre the target.
    @param base: the offset base (a linear address)
    @param tdelta: a displacement from the target which will be displayed
              in the expression.

    @return: success (boolean)
    """
    return idaapi.op_offset(ea, n, reftype, target, base, tdelta)


REF_OFF8    = idaapi.REF_OFF8    # 8bit full offset
REF_OFF16   = idaapi.REF_OFF16   # 16bit full offset
REF_OFF32   = idaapi.REF_OFF32   # 32bit full offset
REF_LOW8    = idaapi.REF_LOW8    # low 8bits of 16bit offset
REF_LOW16   = idaapi.REF_LOW16   # low 16bits of 32bit offset
REF_HIGH8   = idaapi.REF_HIGH8   # high 8bits of 16bit offset
REF_HIGH16  = idaapi.REF_HIGH16  # high 16bits of 32bit offset
REF_VHIGH   = idaapi.REF_VHIGH   # high ph.high_fixup_bits of 32bit offset (processor dependent)
REF_VLOW    = idaapi.REF_VLOW    # low  (32-ph.high_fixup_bits) of 32bit offset (processor dependent)
REF_OFF64   = idaapi.REF_OFF64   # 64bit full offset
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

def OpSeg(ea, n):
    """
    Convert operand to a segment expression

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_seg(ea, n)


def OpNumber(ea, n):
    """
    Convert operand to a number (with default number base, radix)

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_num(ea, n)


def OpFloat(ea, n):
    """
    Convert operand to a floating-point number

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands

    @return: 1-ok, 0-failure
    """
    return idaapi.op_flt(ea, n)


def OpAlt(ea, n, opstr):
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
    return idaapi.set_forced_operand(ea, n, opstr)


def OpSign(ea, n):
    """
    Change sign of the operand

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.toggle_sign(ea, n)


def OpNot(ea, n):
    """
    Toggle the bitwise not operator for the operand

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    idaapi.toggle_bnot(ea, n)
    return True


def OpEnumEx(ea, n, enumid, serial):
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
    return idaapi.op_enum(ea, n, enumid, serial)


def OpStroffEx(ea, n, strid, delta):
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
    path = idaapi.tid_array(1)
    path[0] = strid
    return idaapi.op_stroff(ea, n, path.cast(), 1, delta)


def OpStkvar(ea, n):
    """
    Convert operand to a stack variable

    @param ea: linear address
    @param n: number of operand
        - 0 - the first operand
        - 1 - the second, third and all other operands
        - -1 - all operands
    """
    return idaapi.op_stkvar(ea, n)


def OpHigh(ea, n, target):
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
    return idaapi.op_offset(ea, n, idaapi.REF_HIGH16, target)


def MakeVar(ea):
    """
    Mark the location as "variable"

    @param ea: address to mark

    @return: None

    @note: All that IDA does is to mark the location as "variable".
    Nothing else, no additional analysis is performed.
    This function may disappear in the future.
    """
    idaapi.doVar(ea, 1)


def ExtLinA(ea, n, line):
    """
    Specify an additional line to display before the generated ones.

    @param ea: linear address
    @param n: number of anterior additional line (0..MAX_ITEM_LINES)
    @param line: the line to display

    @return: None

    @note: IDA displays additional lines from number 0 up to the first unexisting
    additional line. So, if you specify additional line #150 and there is no
    additional line #149, your line will not be displayed.  MAX_ITEM_LINES is
    defined in IDA.CFG
    """
    idaapi.update_extra_cmt(ea, idaapi.E_PREV + n, line)
    idaapi.doExtra(ea)


def ExtLinB(ea, n, line):
    """
    Specify an additional line to display after the generated ones.

    @param ea: linear address
    @param n: number of posterior additional line (0..MAX_ITEM_LINES)
    @param line: the line to display

    @return: None

    @note: IDA displays additional lines from number 0 up to the first
    unexisting additional line. So, if you specify additional line #150
    and there is no additional line #149, your line will not be displayed.
    MAX_ITEM_LINES is defined in IDA.CFG
    """
    idaapi.update_extra_cmt(ea, idaapi.E_NEXT + n, line)
    idaapi.doExtra(ea)


def DelExtLnA(ea, n):
    """
    Delete an additional anterior line

    @param ea: linear address
    @param n: number of anterior additional line (0..500)

    @return: None
    """
    idaapi.del_extra_cmt(ea, idaapi.E_PREV + n)


def DelExtLnB(ea, n):
    """
    Delete an additional posterior line

    @param ea: linear address
    @param n: number of posterior additional line (0..500)

    @return: None
    """
    idaapi.del_extra_cmt(ea, idaapi.E_NEXT + n)


def SetManualInsn(ea, insn):
    """
    Specify instruction represenation manually.

    @param ea: linear address
    @param insn: a string represenation of the operand

    @note: IDA will not check the specified instruction, it will simply
    display it instead of the orginal representation.
    """
    return idaapi.set_manual_insn(ea, insn)


def GetManualInsn(ea):
    """
    Get manual representation of instruction

    @param ea: linear address

    @note: This function returns value set by SetManualInsn earlier.
    """
    return idaapi.get_manual_insn(ea)


def PatchDbgByte(ea,value):
    """
    Change a byte in the debugged process memory only

    @param ea: address
    @param value: new value of the byte

    @return: 1 if successful, 0 if not
    """
    return idaapi.put_dbg_byte(ea, value)


def PatchByte(ea, value):
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
    return idaapi.patch_byte(ea, value)


def PatchWord(ea, value):
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
    return idaapi.patch_word(ea, value)


def PatchDword(ea, value):
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
    return idaapi.patch_long(ea, value)


def PatchQword(ea, value):
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
    return idaapi.patch_qword(ea, value)


def SetFlags(ea, flags):
    """
    Set new value of flags
    This function should not used be used directly if possible.
    It changes properties of a program byte and if misused, may lead to
    very-very strange results.

    @param ea: adress
    @param flags: new flags value
    """
    return idaapi.setFlags(ea, flags)

def SetRegEx(ea, reg, value, tag):
    """
    Set value of a segment register.

    @param ea: linear address
    @param reg: name of a register, like "cs", "ds", "es", etc.
    @param value: new value of the segment register.
    @param tag: of SR_... constants

    @note: IDA keeps tracks of all the points where segment register change their
           values. This function allows you to specify the correct value of a segment
           register if IDA is not able to find the corrent value.

           See also SetReg() compatibility macro.
    """
    reg = idaapi.str2reg(reg);
    if reg >= 0:
        return idaapi.splitSRarea1(ea, reg, value, tag)
    else:
        return False

SR_inherit      = 1 # value is inherited from the previous area
SR_user         = 2 # value is specified by the user
SR_auto         = 3 # value is determined by IDA
SR_autostart    = 4 # as SR_auto for segment starting address


def AutoMark2(start, end, queuetype):
    """
    Plan to perform an action in the future.
    This function will put your request to a special autoanalysis queue.
    Later IDA will retrieve the request from the queue and process
    it. There are several autoanalysis queue types. IDA will process all
    queries from the first queue and then switch to the second queue, etc.
    """
    return idaapi.auto_mark_range(start, end, queuetype)


def AutoUnmark(start, end, queuetype):
    """
    Remove range of addresses from a queue.
    """
    return idaapi.autoUnmark(start, end, queuetype)


def AutoMark(ea,qtype):
    """
    Plan to analyze an address
    """
    return AutoMark2(ea,ea+1,qtype)

AU_UNK   = idaapi.AU_UNK   # make unknown
AU_CODE  = idaapi.AU_CODE  # convert to instruction
AU_PROC  = idaapi.AU_PROC  # make function
AU_USED  = idaapi.AU_USED  # reanalyze
AU_LIBF  = idaapi.AU_LIBF  # apply a flirt signature (the current signature!)
AU_FINAL = idaapi.AU_FINAL # coagulate unexplored items


#----------------------------------------------------------------------------
#               P R O D U C E   O U T P U T   F I L E S
#----------------------------------------------------------------------------

def GenerateFile(filetype, path, ea1, ea2, flags):
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
    f = idaapi.fopenWT(path)

    if f:
        retval = idaapi.gen_file(filetype, f, ea1, ea2, flags)
        idaapi.eclose(f)
        return retval
    else:
        return -1


# output file types:
OFILE_MAP  = idaapi.OFILE_MAP
OFILE_EXE  = idaapi.OFILE_EXE
OFILE_IDC  = idaapi.OFILE_IDC
OFILE_LST  = idaapi.OFILE_LST
OFILE_ASM  = idaapi.OFILE_ASM
OFILE_DIF  = idaapi.OFILE_DIF

# output control flags:
GENFLG_MAPSEG  = idaapi.GENFLG_MAPSEG  # map: generate map of segments
GENFLG_MAPNAME = idaapi.GENFLG_MAPNAME # map: include dummy names
GENFLG_MAPDMNG = idaapi.GENFLG_MAPDMNG # map: demangle names
GENFLG_MAPLOC  = idaapi.GENFLG_MAPLOC  # map: include local names
GENFLG_IDCTYPE = idaapi.GENFLG_IDCTYPE # idc: gen only information about types
GENFLG_ASMTYPE = idaapi.GENFLG_ASMTYPE # asm&lst: gen information about types too
GENFLG_GENHTML = idaapi.GENFLG_GENHTML # asm&lst: generate html (gui version only)
GENFLG_ASMINC  = idaapi.GENFLG_ASMINC  # asm&lst: gen information only about types

def GenFuncGdl(outfile, title, ea1, ea2, flags):
    """
    Generate a flow chart GDL file

    @param outfile: output file name. GDL extension will be used
    @param title: graph title
    @param ea1: beginning of the area to flow chart
    @param ea2: end of the area to flow chart.
    @param flags: combination of CHART_... constants

    @note: If ea2 == BADADDR then ea1 is treated as an address within a function.
           That function will be flow charted.
    """
    return idaapi.gen_flow_graph(outfile, title, None, ea1, ea2, flags)


CHART_PRINT_NAMES = 0x1000 # print labels for each block?
CHART_GEN_GDL     = 0x4000 # generate .gdl file (file extension is forced to .gdl)
CHART_WINGRAPH    = 0x8000 # call wingraph32 to display the graph
CHART_NOLIBFUNCS  = 0x0400 # don't include library functions in the graph


def GenCallGdl(outfile, title, flags):
    """
    Generate a function call graph GDL file

    @param outfile: output file name. GDL extension will be used
    @param title:   graph title
    @param flags:   combination of CHART_GEN_GDL, CHART_WINGRAPH, CHART_NOLIBFUNCS
    """
    return idaapi.gen_simple_call_chart(outfile, "Generating chart", title, flags)


#----------------------------------------------------------------------------
#                 C O M M O N   I N F O R M A T I O N
#----------------------------------------------------------------------------
def GetIdaDirectory():
    """
    Get IDA directory

    This function returns the directory where IDA.EXE resides
    """
    return idaapi.idadir("")


def GetInputFile():
    """
    Get input file name

    This function returns name of the file being disassembled
    """
    return idaapi.get_root_filename()


def GetInputFilePath():
    """
    Get input file path

    This function returns the full path of the file being disassembled
    """
    return idaapi.get_input_file_path()


def SetInputFilePath(path):
    """
    Set input file name
    This function updates the file name that is stored in the database
    It is used by the debugger and other parts of IDA
    Use it when the database is moved to another location or when you
    use remote debugging.

    @param path: new input file path
    """
    return idaapi.set_root_filename(path)


def GetIdbPath():
    """
    Get IDB full path

    This function returns full path of the current IDB database
    """
    return idaapi.as_cstr(idaapi.cvar.database_idb)


def GetInputMD5():
    """
    Return the MD5 hash of the input binary file

    @return: MD5 string or None on error
    """
    ua = idaapi.uchar_array(16)
    if idaapi.retrieve_input_file_md5(ua.cast()):
        return "".join(["%02X" % ua[i] for i in xrange(16)])
    else:
        return None


def GetFlags(ea):
    """
    Get internal flags

    @param ea: linear address

    @return: 32-bit value of internal flags. See start of IDC.IDC file
        for explanations.
    """
    return idaapi.getFlags(ea)


def IdbByte(ea):
    """
    Get one byte (8-bit) of the program at 'ea' from the database even if the debugger is active

    @param ea: linear address

    @return: byte value. If the byte has no value then 0xFF is returned.

    @note: If the current byte size is different from 8 bits, then the returned value may have more 1's.
           To check if a byte has a value, use this expr: hasValue(GetFlags(ea))
    """
    return idaapi.get_db_byte(ea)


def GetManyBytes(ea, size, use_dbg = False):
    """
    Return the specified number of bytes of the program

    @param ea: linear address

    @param size: size of buffer in normal 8-bit bytes

    @param use_dbg: if True, use debugger memory, otherwise just the database

    @return: None on failure
             otherwise a string containing the read bytes
    """
    if use_dbg:
        return idaapi.dbg_read_memory(ea, size)
    else:
        return idaapi.get_many_bytes(ea, size)


def Byte(ea):
    """
    Get value of program byte

    @param ea: linear address

    @return: value of byte. If byte has no value then returns 0xFF
        If the current byte size is different from 8 bits, then the returned value
        might have more 1's.
        To check if a byte has a value, use functions hasValue(GetFlags(ea))
    """
    return idaapi.get_full_byte(ea)


def __DbgValue(ea, len):
    if len not in idaapi.__struct_unpack_table:
        return None
    r = idaapi.dbg_read_memory(ea, len)
    return None if r is None else struct.unpack((">" if idaapi.cvar.inf.mf else "<") + idaapi.__struct_unpack_table[len][1], r)[0]


def DbgByte(ea):
    """
    Get value of program byte using the debugger memory

    @param ea: linear address
    @return: The value or None on failure.
    """
    return __DbgValue(ea, 1)


def DbgWord(ea):
    """
    Get value of program word using the debugger memory

    @param ea: linear address
    @return: The value or None on failure.
    """
    return __DbgValue(ea, 2)


def DbgDword(ea):
    """
    Get value of program double-word using the debugger memory

    @param ea: linear address
    @return: The value or None on failure.
    """
    return __DbgValue(ea, 4)


def DbgQword(ea):
    """
    Get value of program quadro-word using the debugger memory

    @param ea: linear address
    @return: The value or None on failure.
    """
    return __DbgValue(ea, 8)


def DbgRead(ea, size):
    """
    Read from debugger memory.

    @param ea: linear address
    @param size: size of data to read
    @return: data as a string. If failed, If failed, throws an exception

    Thread-safe function (may be called only from the main thread and debthread)
    """
    return idaapi.dbg_read_memory(ea, size)


def DbgWrite(ea, data):
    """
    Write to debugger memory.

    @param ea: linear address
    @param data: string to write
    @return: number of written bytes (-1 - network/debugger error)

    Thread-safe function (may be called only from the main thread and debthread)
    """
    if not idaapi.dbg_can_query():
        return -1
    elif len(data) > 0:
        return idaapi.dbg_write_memory(ea, data)


def GetOriginalByte(ea):
    """
    Get original value of program byte

    @param ea: linear address

    @return: the original value of byte before any patch applied to it
    """
    return idaapi.get_original_byte(ea)


def Word(ea):
    """
    Get value of program word (2 bytes)

    @param ea: linear address

    @return: the value of the word. If word has no value then returns 0xFFFF
        If the current byte size is different from 8 bits, then the returned value
        might have more 1's.
    """
    return idaapi.get_full_word(ea)


def Dword(ea):
    """
    Get value of program double word (4 bytes)

    @param ea: linear address

    @return: the value of the double word. If failed returns -1
    """
    return idaapi.get_full_long(ea)


def Qword(ea):
    """
    Get value of program quadro word (8 bytes)

    @param ea: linear address

    @return: the value of the quadro word. If failed, returns -1
    """
    return idaapi.get_qword(ea)


def GetFloat(ea):
    """
    Get value of a floating point number (4 bytes)
    This function assumes number stored using IEEE format
    and in the same endianness as integers.

    @param ea: linear address

    @return: float
    """
    tmp = struct.pack("I", Dword(ea))
    return struct.unpack("f", tmp)[0]


def GetDouble(ea):
    """
    Get value of a floating point number (8 bytes)
    This function assumes number stored using IEEE format
    and in the same endianness as integers.

    @param ea: linear address

    @return: double
    """
    tmp = struct.pack("Q", Qword(ea))
    return struct.unpack("d", tmp)[0]


def LocByName(name):
    """
    Get linear address of a name

    @param name: name of program byte

    @return: address of the name
             BADADDR - No such name
    """
    return idaapi.get_name_ea(BADADDR, name)


def LocByNameEx(fromaddr, name):
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
    return idaapi.get_name_ea(fromaddr, name)


def SegByBase(base):
    """
    Get segment by segment base

    @param base: segment base paragraph or selector

    @return: linear address of the start of the segment or BADADDR
             if no such segment
    """
    sel = idaapi.find_selector(base)
    seg = idaapi.get_segm_by_sel(sel)

    if seg:
        return seg.startEA
    else:
        return BADADDR


def ScreenEA():
    """
    Get linear address of cursor
    """
    return idaapi.get_screen_ea()


def GetCurrentLine():
    """
    Get the disassembly line at the cursor

    @return: string
    """
    return idaapi.tag_remove(idaapi.get_curline())


def SelStart():
    """
    Get start address of the selected area
    returns BADADDR - the user has not selected an area
    """
    selection, startaddr, endaddr = idaapi.read_selection()

    if selection == 1:
        return startaddr
    else:
        return BADADDR


def SelEnd():
    """
    Get end address of the selected area

    @return: BADADDR - the user has not selected an area
    """
    selection, startaddr, endaddr = idaapi.read_selection()

    if selection == 1:
        return endaddr
    else:
        return BADADDR


def GetReg(ea, reg):
    """
    Get value of segment register at the specified address

    @param ea: linear address
    @param reg: name of segment register

    @return: the value of the segment register or -1 on error

    @note: The segment registers in 32bit program usually contain selectors,
           so to get paragraph pointed by the segment register you need to
           call AskSelector() function.
    """
    reg = idaapi.str2reg(reg);
    if reg >= 0:
        return idaapi.getSR(ea, reg)
    else:
        return -1

def NextAddr(ea):
    """
    Get next address in the program

    @param ea: linear address

    @return: BADADDR - the specified address in the last used address
    """
    return idaapi.nextaddr(ea)


def PrevAddr(ea):
    """
    Get previous address in the program

    @param ea: linear address

    @return: BADADDR - the specified address in the first address
    """
    return idaapi.prevaddr(ea)


def NextHead(ea, maxea=BADADDR):
    """
    Get next defined item (instruction or data) in the program

    @param ea: linear address to start search from
    @param maxea: the search will stop at the address
        maxea is not included in the search range

    @return: BADADDR - no (more) defined items
    """
    return idaapi.next_head(ea, maxea)


def PrevHead(ea, minea=0):
    """
    Get previous defined item (instruction or data) in the program

    @param ea: linear address to start search from
    @param minea: the search will stop at the address
            minea is included in the search range

    @return: BADADDR - no (more) defined items
    """
    return idaapi.prev_head(ea, minea)


def NextNotTail(ea):
    """
    Get next not-tail address in the program
    This function searches for the next displayable address in the program.
    The tail bytes of instructions and data are not displayable.

    @param ea: linear address

    @return: BADADDR - no (more) not-tail addresses
    """
    return idaapi.next_not_tail(ea)


def PrevNotTail(ea):
    """
    Get previous not-tail address in the program
    This function searches for the previous displayable address in the program.
    The tail bytes of instructions and data are not displayable.

    @param ea: linear address

    @return: BADADDR - no (more) not-tail addresses
    """
    return idaapi.prev_not_tail(ea)


def ItemHead(ea):
    """
    Get starting address of the item (instruction or data)

    @param ea: linear address

    @return: the starting address of the item
             if the current address is unexplored, returns 'ea'
    """
    return idaapi.get_item_head(ea)


def ItemEnd(ea):
    """
    Get address of the end of the item (instruction or data)

    @param ea: linear address

    @return: address past end of the item at 'ea'
    """
    return idaapi.get_item_end(ea)


def ItemSize(ea):
    """
    Get size of instruction or data item in bytes

    @param ea: linear address

    @return: 1..n
    """
    return idaapi.get_item_end(ea) - ea


def NameEx(fromaddr, ea):
    """
    Get visible name of program byte

    This function returns name of byte as it is displayed on the screen.
    If a name contains illegal characters, IDA replaces them by the
    substitution character during displaying. See IDA.CFG for the
    definition of the substitution character.

    @param fromaddr: the referring address. May be BADADDR.
               Allows to retrieve local label addresses in functions.
               If a local name is not found, then a global name is
               returned.
    @param ea: linear address

    @return: "" - byte has no name
    """
    name = idaapi.get_name(fromaddr, ea)

    if not name:
        return ""
    else:
        return name


def GetTrueNameEx(fromaddr, ea):
    """
    Get true name of program byte

    This function returns name of byte as is without any replacements.

    @param fromaddr: the referring address. May be BADADDR.
           Allows to retrieve local label addresses in functions.
           If a local name is not found, then a global name is returned.
    @param ea: linear address

    @return: "" - byte has no name
    """
    name = idaapi.get_true_name(fromaddr, ea)

    if not name:
        return ""
    else:
        return name


def Demangle(name, disable_mask):
    """
    Demangle a name

    @param name: name to demangle
    @param disable_mask: a mask that tells how to demangle the name
            it is a good idea to get this mask using
            GetLongPrm(INF_SHORT_DN) or GetLongPrm(INF_LONG_DN)

    @return: a demangled name
        If the input name cannot be demangled, returns None
    """
    return idaapi.demangle_name(name, disable_mask)


def GetDisasmEx(ea, flags):
    """
    Get disassembly line

    @param ea: linear address of instruction

    @param flags: combination of the GENDSM_ flags, or 0

    @return: "" - could not decode instruction at the specified location

    @note: this function may not return exactly the same mnemonics
           as you see on the screen.
    """
    text = idaapi.generate_disasm_line(ea, flags)
    if text:
        return idaapi.tag_remove(text)
    else:
        return ""

# flags for GetDisasmEx
# generate a disassembly line as if
# there is an instruction at 'ea'
GENDSM_FORCE_CODE = idaapi.GENDSM_FORCE_CODE

# if the instruction consists of several lines,
# produce all of them (useful for parallel instructions)
GENDSM_MULTI_LINE = idaapi.GENDSM_MULTI_LINE

def GetDisasm(ea):
    """
    Get disassembly line

    @param ea: linear address of instruction

    @return: "" - could not decode instruction at the specified location

    @note: this function may not return exactly the same mnemonics
           as you see on the screen.
    """
    return GetDisasmEx(ea, 0)

def GetMnem(ea):
    """
    Get instruction mnemonics

    @param ea: linear address of instruction

    @return: "" - no instruction at the specified location

    @note: this function may not return exactly the same mnemonics
    as you see on the screen.
    """
    res = idaapi.ua_mnem(ea)

    if not res:
        return ""
    else:
        return res


def GetOpnd(ea, n):
    """
    Get operand of an instruction

    @param ea: linear address of instruction
    @param n: number of operand:
        0 - the first operand
        1 - the second operand

    @return: the current text representation of operand or ""
    """

    if not isCode(idaapi.get_flags_novalue(ea)):
        return ""

    res = idaapi.ua_outop2(ea, n)

    if not res:
        return ""
    else:
        return idaapi.tag_remove(res)


def GetOpType(ea, n):
    """
    Get type of instruction operand

    @param ea: linear address of instruction
    @param n: number of operand:
        0 - the first operand
        1 - the second operand

    @return: any of o_* constants or -1 on error
    """
    inslen = idaapi.decode_insn(ea)
    return -1 if inslen == 0 else idaapi.cmd.Operands[n].type


o_void     = idaapi.o_void      # No Operand                           ----------
o_reg      = idaapi.o_reg       # General Register (al,ax,es,ds...)    reg
o_mem      = idaapi.o_mem       # Direct Memory Reference  (DATA)      addr
o_phrase   = idaapi.o_phrase    # Memory Ref [Base Reg + Index Reg]    phrase
o_displ    = idaapi.o_displ     # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
o_imm      = idaapi.o_imm       # Immediate Value                      value
o_far      = idaapi.o_far       # Immediate Far Address  (CODE)        addr
o_near     = idaapi.o_near      # Immediate Near Address (CODE)        addr
o_idpspec0 = idaapi.o_idpspec0  # Processor specific type
o_idpspec1 = idaapi.o_idpspec1  # Processor specific type
o_idpspec2 = idaapi.o_idpspec2  # Processor specific type
o_idpspec3 = idaapi.o_idpspec3  # Processor specific type
o_idpspec4 = idaapi.o_idpspec4  # Processor specific type
o_idpspec5 = idaapi.o_idpspec5  # Processor specific type
                                # There can be more processor specific types

# x86
o_trreg  =       idaapi.o_idpspec0      # trace register
o_dbreg  =       idaapi.o_idpspec1      # debug register
o_crreg  =       idaapi.o_idpspec2      # control register
o_fpreg  =       idaapi.o_idpspec3      # floating point register
o_mmxreg  =      idaapi.o_idpspec4      # mmx register
o_xmmreg  =      idaapi.o_idpspec5      # xmm register

# arm
o_reglist  =     idaapi.o_idpspec1      # Register list (for LDM/STM)
o_creglist  =    idaapi.o_idpspec2      # Coprocessor register list (for CDP)
o_creg  =        idaapi.o_idpspec3      # Coprocessor register (for LDC/STC)
o_fpreg_arm  =   idaapi.o_idpspec4      # Floating point register
o_fpreglist  =   idaapi.o_idpspec5      # Floating point register list
o_text  =        (idaapi.o_idpspec5+1)  # Arbitrary text stored in the operand

# ppc
o_spr  =         idaapi.o_idpspec0      # Special purpose register
o_twofpr  =      idaapi.o_idpspec1      # Two FPRs
o_shmbme  =      idaapi.o_idpspec2      # SH & MB & ME
o_crf  =         idaapi.o_idpspec3      # crfield      x.reg
o_crb  =         idaapi.o_idpspec4      # crbit        x.reg
o_dcr  =         idaapi.o_idpspec5      # Device control register

def GetOperandValue(ea, n):
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
    inslen = idaapi.decode_insn(ea)
    if inslen == 0:
        return -1
    op = idaapi.cmd.Operands[n]
    if not op:
        return -1

    if op.type in [ idaapi.o_mem, idaapi.o_far, idaapi.o_near, idaapi.o_displ ]:
        value = op.addr
    elif op.type == idaapi.o_reg:
        value = op.reg
    elif op.type == idaapi.o_imm:
        value = op.value
    elif op.type == idaapi.o_phrase:
        value = op.phrase
    else:
        value = -1
    return value


def LineA(ea, num):
    """
    Get anterior line

    @param ea: linear address
    @param num: number of anterior line (0..MAX_ITEM_LINES)
          MAX_ITEM_LINES is defined in IDA.CFG

    @return: anterior line string
    """
    return idaapi.get_extra_cmt(ea, idaapi.E_PREV + num)


def LineB(ea, num):
    """
    Get posterior line

    @param ea: linear address
    @param num: number of posterior line (0..MAX_ITEM_LINES)

    @return: posterior line string
    """
    return idaapi.get_extra_cmt(ea, idaapi.E_NEXT + num)


def GetCommentEx(ea, repeatable):
    """
    Get regular indented comment

    @param ea: linear address

    @param repeatable: 1 to get the repeatable comment, 0 to get the normal comment

    @return: string or None if it fails
    """
    return idaapi.get_cmt(ea, repeatable)


def CommentEx(ea, repeatable):
    """
    Get regular indented comment

    @param ea: linear address

    @param repeatable: 1 to get the repeatable comment, 0 to get the normal comment

    @return: string or None if it fails
    """
    return GetCommentEx(ea, repeatable)


def AltOp(ea, n):
    """
    Get manually entered operand string

    @param ea: linear address
    @param n: number of operand:
         0 - the first operand
         1 - the second operand

    @return: string or None if it fails
    """
    return idaapi.get_forced_operand(ea, n)

ASCSTR_C       = idaapi.ASCSTR_TERMCHR # C-style ASCII string
ASCSTR_PASCAL  = idaapi.ASCSTR_PASCAL  # Pascal-style ASCII string (length byte)
ASCSTR_LEN2    = idaapi.ASCSTR_LEN2    # Pascal-style, length is 2 bytes
ASCSTR_UNICODE = idaapi.ASCSTR_UNICODE # Unicode string
ASCSTR_LEN4    = idaapi.ASCSTR_LEN4    # Pascal-style, length is 4 bytes
ASCSTR_ULEN2   = idaapi.ASCSTR_ULEN2   # Pascal-style Unicode, length is 2 bytes
ASCSTR_ULEN4   = idaapi.ASCSTR_ULEN4   # Pascal-style Unicode, length is 4 bytes
ASCSTR_LAST    = idaapi.ASCSTR_LAST    # Last string type

def GetString(ea, length = -1, strtype = ASCSTR_C):
    """
    Get string contents
    @param ea: linear address
    @param length: string length. -1 means to calculate the max string length
    @param strtype: the string type (one of ASCSTR_... constants)

    @return: string contents or empty string
    """
    if length == -1:
        length = idaapi.get_max_ascii_length(ea, strtype, idaapi.ALOPT_IGNHEADS)

    return idaapi.get_ascii_contents2(ea, length, strtype)


def GetStringType(ea):
    """
    Get string type

    @param ea: linear address

    @return: One of ASCSTR_... constants
    """
    ti = idaapi.opinfo_t()

    if idaapi.get_opinfo(ea, 0, GetFlags(ea), ti):
        return ti.strtype
    else:
        return None

#      The following functions search for the specified byte
#          ea - address to start from
#          flag is combination of the following bits

#      returns BADADDR - not found
def FindVoid        (ea, flag): return idaapi.find_void(ea, flag)
def FindCode        (ea, flag): return idaapi.find_code(ea, flag)
def FindData        (ea, flag): return idaapi.find_data(ea, flag)
def FindUnexplored  (ea, flag): return idaapi.find_unknown(ea, flag)
def FindExplored    (ea, flag): return idaapi.find_defined(ea, flag)
def FindImmediate   (ea, flag, value): return idaapi.find_imm(ea, flag, value)

SEARCH_UP       = idaapi.SEARCH_UP       # search backward
SEARCH_DOWN     = idaapi.SEARCH_DOWN     # search forward
SEARCH_NEXT     = idaapi.SEARCH_NEXT     # start the search at the next/prev item
                                         # useful only for FindText() and FindBinary()
SEARCH_CASE     = idaapi.SEARCH_CASE     # search case-sensitive
                                         # (only for bin&txt search)
SEARCH_REGEX    = idaapi.SEARCH_REGEX    # enable regular expressions (only for text)
SEARCH_NOBRK    = idaapi.SEARCH_NOBRK    # don't test ctrl-break
SEARCH_NOSHOW   = idaapi.SEARCH_NOSHOW   # don't display the search progress

def FindText(ea, flag, y, x, searchstr):
    """
    @param ea: start address
    @param flag: combination of SEARCH_* flags
    @param y: number of text line at ea to start from (0..MAX_ITEM_LINES)
    @param x: coordinate in this line
    @param searchstr: search string

    @return: ea of result or BADADDR if not found
    """
    return idaapi.find_text(ea, y, x, searchstr, flag)


def FindBinary(ea, flag, searchstr, radix=16):
    """
    @param ea: start address
    @param flag: combination of SEARCH_* flags
    @param searchstr: a string as a user enters it for Search Text in Core
    @param radix: radix of the numbers (default=16)

    @return: ea of result or BADADDR if not found

    @note: Example: "41 42" - find 2 bytes 41h,42h (radix is 16)
    """
    endea = flag & 1 and idaapi.cvar.inf.maxEA or idaapi.cvar.inf.minEA
    return idaapi.find_binary(ea, endea, searchstr, radix, flag)


#----------------------------------------------------------------------------
#       G L O B A L   S E T T I N G S   M A N I P U L A T I O N
#----------------------------------------------------------------------------
def ChangeConfig(directive):
    """
    Parse one or more ida.cfg config directives
    @param directive: directives to process, for example: PACK_DATABASE=2

    @note: If the directives are erroneous, a fatal error will be generated.
           The settings are permanent: effective for the current session and the next ones
    """
    return Eval('ChangeConfig("%s")' % idaapi.str2user(directive))


# The following functions allow you to set/get common parameters.
# Please note that not all parameters can be set directly.

def GetLongPrm(offset):
    """
    """
    val = _IDC_GetAttr(idaapi.cvar.inf, _INFMAP, offset)
    if offset == INF_PROCNAME:
        # procName is a character array
        val = idaapi.as_cstr(val)
    return val

def GetShortPrm(offset):
    return GetLongPrm(offset)


def GetCharPrm (offset):
    return GetLongPrm(offset)


def SetLongPrm (offset, value):
    """
    """
    if offset == INF_PROCNAME:
        raise NotImplementedError, "Please use idaapi.set_processor_type() to change processor"
    return _IDC_SetAttr(idaapi.cvar.inf, _INFMAP, offset, value)


def SetShortPrm(offset, value):
    SetLongPrm(offset, value)


def SetCharPrm (offset, value):
    SetLongPrm(offset, value)


INF_VERSION     = 3       # short;   Version of database
INF_PROCNAME    = 5       # char[8]; Name of current processor
INF_LFLAGS      = 13      # char;    IDP-dependent flags
LFLG_PC_FPP     = 0x01    #              decode floating point processor
                          #              instructions?
LFLG_PC_FLAT    = 0x02    #              Flat model?
LFLG_64BIT      = 0x04    #              64-bit program?
LFLG_DBG_NOPATH = 0x08    #              do not store input full path
LFLG_SNAPSHOT   = 0x10    #              is memory snapshot?
                          #              in debugger process options
INF_DEMNAMES    = 14      # char;    display demangled names as:
DEMNAM_CMNT  = 0          #              comments
DEMNAM_NAME  = 1          #              regular names
DEMNAM_NONE  = 2          #              don't display
INF_FILETYPE    = 15      # short;   type of input file (see ida.hpp)
FT_EXE_OLD      = 0       #              MS DOS EXE File (obsolete)
FT_COM_OLD      = 1       #              MS DOS COM File (obsolete)
FT_BIN          = 2       #              Binary File
FT_DRV          = 3       #              MS DOS Driver
FT_WIN          = 4       #              New Executable (NE)
FT_HEX          = 5       #              Intel Hex Object File
FT_MEX          = 6       #              MOS Technology Hex Object File
FT_LX           = 7       #              Linear Executable (LX)
FT_LE           = 8       #              Linear Executable (LE)
FT_NLM          = 9       #              Netware Loadable Module (NLM)
FT_COFF         = 10      #              Common Object File Format (COFF)
FT_PE           = 11      #              Portable Executable (PE)
FT_OMF          = 12      #              Object Module Format
FT_SREC         = 13      #              R-records
FT_ZIP          = 14      #              ZIP file (this file is never loaded to IDA database)
FT_OMFLIB       = 15      #              Library of OMF Modules
FT_AR           = 16      #              ar library
FT_LOADER       = 17      #              file is loaded using LOADER DLL
FT_ELF          = 18      #              Executable and Linkable Format (ELF)
FT_W32RUN       = 19      #              Watcom DOS32 Extender (W32RUN)
FT_AOUT         = 20      #              Linux a.out (AOUT)
FT_PRC          = 21      #              PalmPilot program file
FT_EXE          = 22      #              MS DOS EXE File
FT_COM          = 23      #              MS DOS COM File
FT_AIXAR        = 24      #              AIX ar library
INF_FCORESIZ    = 17
INF_CORESTART   = 21
INF_OSTYPE      = 25      # short;   FLIRT: OS type the program is for
OSTYPE_MSDOS = 0x0001
OSTYPE_WIN   = 0x0002
OSTYPE_OS2   = 0x0004
OSTYPE_NETW  = 0x0008
INF_APPTYPE     = 27      # short;   FLIRT: Application type
APPT_CONSOLE = 0x0001     #              console
APPT_GRAPHIC = 0x0002     #              graphics
APPT_PROGRAM = 0x0004     #              EXE
APPT_LIBRARY = 0x0008     #              DLL
APPT_DRIVER  = 0x0010     #              DRIVER
APPT_1THREAD = 0x0020     #              Singlethread
APPT_MTHREAD = 0x0040     #              Multithread
APPT_16BIT   = 0x0080     #              16 bit application
APPT_32BIT   = 0x0100     #              32 bit application
INF_START_SP    = 29      # long;    SP register value at the start of
                          #          program execution
INF_START_AF    = 33      # short;   Analysis flags:
AF_FIXUP        = 0x0001  #              Create offsets and segments using fixup info
AF_MARKCODE     = 0x0002  #              Mark typical code sequences as code
AF_UNK          = 0x0004  #              Delete instructions with no xrefs
AF_CODE         = 0x0008  #              Trace execution flow
AF_PROC         = 0x0010  #              Create functions if call is present
AF_USED         = 0x0020  #              Analyze and create all xrefs
AF_FLIRT        = 0x0040  #              Use flirt signatures
AF_PROCPTR      = 0x0080  #              Create function if data xref data->code32 exists
AF_JFUNC        = 0x0100  #              Rename jump functions as j_...
AF_NULLSUB      = 0x0200  #              Rename empty functions as nullsub_...
AF_LVAR         = 0x0400  #              Create stack variables
AF_TRACE        = 0x0800  #              Trace stack pointer
AF_ASCII        = 0x1000  #              Create ascii string if data xref exists
AF_IMMOFF       = 0x2000  #              Convert 32bit instruction operand to offset
AF_DREFOFF      = 0x4000  #              Create offset if data xref to seg32 exists
AF_FINAL        = 0x8000  #              Final pass of analysis
INF_START_IP    = 35      # long;    IP register value at the start of
                          #          program execution
INF_BEGIN_EA    = 39      # long;    Linear address of program entry point
INF_MIN_EA      = 43      # long;    The lowest address used
                          #          in the program
INF_MAX_EA      = 47      # long;    The highest address used
                          #          in the program - = 1
INF_OMIN_EA     = 51
INF_OMAX_EA     = 55
INF_LOW_OFF     = 59      # long;    low limit of voids
INF_HIGH_OFF    = 63      # long;    high limit of voids
INF_MAXREF      = 67      # long;    max xref depth
INF_ASCII_BREAK = 71      # char;    ASCII line break symbol
INF_WIDE_HIGH_BYTE_FIRST = 72
INF_INDENT      = 73      # char;    Indention for instructions
INF_COMMENT     = 74      # char;    Indention for comments
INF_XREFNUM     = 75      # char;    Number of references to generate
                          #          = 0 - xrefs wont be generated at all
INF_ENTAB       = 76      # char;    Use '\t' chars in the output file?
INF_SPECSEGS    = 77
INF_VOIDS       = 78      # char;    Display void marks?
INF_SHOWAUTO    = 80      # char;    Display autoanalysis indicator?
INF_AUTO        = 81      # char;    Autoanalysis is enabled?
INF_BORDER      = 82      # char;    Generate borders?
INF_NULL        = 83      # char;    Generate empty lines?
INF_GENFLAGS    = 84      # char;    General flags:
INFFL_LZERO     = 0x01    #              generate leading zeroes in numbers
INFFL_LOADIDC   = 0x04    #              Loading an idc file t
INF_SHOWPREF    = 85      # char;    Show line prefixes?
INF_PREFSEG     = 86      # char;    line prefixes with segment name?
INF_ASMTYPE     = 87      # char;    target assembler number (0..n)
INF_BASEADDR    = 88      # long;    base paragraph of the program
INF_XREFS       = 92      # char;    xrefs representation:
SW_SEGXRF       = 0x01    #              show segments in xrefs?
SW_XRFMRK       = 0x02    #              show xref type marks?
SW_XRFFNC       = 0x04    #              show function offsets?
SW_XRFVAL       = 0x08    #              show xref values? (otherwise-"...")
INF_BINPREF     = 93      # short;   # of instruction bytes to show
                          #          in line prefix
INF_CMTFLAG     = 95      # char;    comments:
SW_RPTCMT       = 0x01    #              show repeatable comments?
SW_ALLCMT       = 0x02    #              comment all lines?
SW_NOCMT        = 0x04    #              no comments at all
SW_LINNUM       = 0x08    #              show source line numbers
SW_MICRO        = 0x10    #              show microcode (if implemented)
INF_NAMETYPE    = 96      # char;    dummy names represenation type
NM_REL_OFF      = 0
NM_PTR_OFF      = 1
NM_NAM_OFF      = 2
NM_REL_EA       = 3
NM_PTR_EA       = 4
NM_NAM_EA       = 5
NM_EA           = 6
NM_EA4          = 7
NM_EA8          = 8
NM_SHORT        = 9
NM_SERIAL       = 10
INF_SHOWBADS    = 97      # char;    show bad instructions?
                          #          an instruction is bad if it appears
                          #          in the ash.badworks array

INF_PREFFLAG    = 98      # char;    line prefix type:
PREF_SEGADR     = 0x01    #              show segment addresses?
PREF_FNCOFF     = 0x02    #              show function offsets?
PREF_STACK      = 0x04    #              show stack pointer?

INF_PACKBASE    = 99      # char;    pack database?

INF_ASCIIFLAGS  = 100     # uchar;   ascii flags
ASCF_GEN        = 0x01    #              generate ASCII names?
ASCF_AUTO       = 0x02    #              ASCII names have 'autogenerated' bit?
ASCF_SERIAL     = 0x04    #              generate serial names?
ASCF_COMMENT    = 0x10    #              generate auto comment for ascii references?
ASCF_SAVECASE   = 0x20    #              preserve case of ascii strings for identifiers

INF_LISTNAMES   = 101     # uchar;   What names should be included in the list?
LN_NORMAL       = 0x01    #              normal names
LN_PUBLIC       = 0x02    #              public names
LN_AUTO         = 0x04    #              autogenerated names
LN_WEAK         = 0x08    #              weak names

INF_ASCIIPREF   = 102     # char[16];ASCII names prefix
INF_ASCIISERNUM = 118     # ulong;   serial number
INF_ASCIIZEROES = 122     # char;    leading zeroes
INF_MF          = 126     # uchar;   Byte order: 1==MSB first
INF_ORG         = 127     # char;    Generate 'org' directives?
INF_ASSUME      = 128     # char;    Generate 'assume' directives?
INF_CHECKARG    = 129     # char;    Check manual operands?
INF_START_SS    = 130     # long;    value of SS at the start
INF_START_CS    = 134     # long;    value of CS at the start
INF_MAIN        = 138     # long;    address of main()
INF_SHORT_DN    = 142     # long;    short form of demangled names
INF_LONG_DN     = 146     # long;    long form of demangled names
                          #          see demangle.h for definitions
INF_DATATYPES   = 150     # long;    data types allowed in data carousel
INF_STRTYPE     = 154     # long;    current ascii string type
                          #          is considered as several bytes:
                          #      low byte:
ASCSTR_TERMCHR  = 0       #              Character-terminated ASCII string
ASCSTR_C        = 0       #              C-string, zero terminated
ASCSTR_PASCAL   = 1       #              Pascal-style ASCII string (length byte)
ASCSTR_LEN2     = 2       #              Pascal-style, length is 2 bytes
ASCSTR_UNICODE  = 3       #              Unicode string
ASCSTR_LEN4     = 4       #              Delphi string, length is 4 bytes
ASCSTR_ULEN2    = 5       #              Pascal-style Unicode, length is 2 bytes
ASCSTR_ULEN4    = 6       #              Pascal-style Unicode, length is 4 bytes

#      = 2nd byte - termination chracters for ASCSTR_TERMCHR:
#STRTERM1(strtype)       ((strtype>>8)&0xFF)
#      = 3d byte:
#STRTERM2(strtype)       ((strtype>>16)&0xFF)
                         #              The termination characters are kept in
                         #              the = 2nd and 3d bytes of string type
                         #              if the second termination character is
                         #              '\0', then it is ignored.
INF_AF2         = 158    # ushort;  Analysis flags 2
AF2_JUMPTBL     = 0x0001  # Locate and create jump tables
AF2_DODATA      = 0x0002  # Coagulate data segs in final pass
AF2_HFLIRT      = 0x0004  # Automatically hide library functions
AF2_STKARG      = 0x0008  # Propagate stack argument information
AF2_REGARG      = 0x0010  # Propagate register argument information
AF2_CHKUNI      = 0x0020  # Check for unicode strings
AF2_SIGCMT      = 0x0040  # Append a signature name comment for recognized anonymous library functions
AF2_SIGMLT      = 0x0080  # Allow recognition of several copies of the same function
AF2_FTAIL       = 0x0100  # Create function tails
AF2_DATOFF      = 0x0200  # Automatically convert data to offsets
AF2_ANORET      = 0x0400  # Perform 'no-return' analysis
AF2_VERSP       = 0x0800  # Perform full stack pointer analysis
AF2_DOCODE      = 0x1000  # Coagulate code segs at the final pass
AF2_TRFUNC      = 0x2000  # Truncate functions upon code deletion
AF2_PURDAT      = 0x4000  # Control flow to data segment is ignored
INF_NAMELEN     = 160    # ushort;  max name length (without zero byte)
INF_MARGIN      = 162    # ushort;  max length of data lines
INF_LENXREF     = 164    # ushort;  max length of line with xrefs
INF_LPREFIX     = 166    # char[16];prefix of local names
                         #          if a new name has this prefix,
                         #          it will be automatically converted to a local name
INF_LPREFIXLEN  = 182    # uchar;   length of the lprefix
INF_COMPILER    = 183    # uchar;   compiler
COMP_MASK       = 0x0F      # mask to apply to get the pure compiler id
COMP_UNK        = 0x00      # Unknown
COMP_MS         = 0x01      # Visual C++
COMP_BC         = 0x02      # Borland C++
COMP_WATCOM     = 0x03      # Watcom C++
COMP_GNU        = 0x06      # GNU C++
COMP_VISAGE     = 0x07      # Visual Age C++
COMP_BP         = 0x08      # Delphi

INF_MODEL       = 184    # uchar;   memory model & calling convention
INF_SIZEOF_INT  = 185    # uchar;   sizeof(int)
INF_SIZEOF_BOOL = 186    # uchar;   sizeof(bool)
INF_SIZEOF_ENUM = 187    # uchar;   sizeof(enum)
INF_SIZEOF_ALGN = 188    # uchar;   default alignment
INF_SIZEOF_SHORT = 189
INF_SIZEOF_LONG  = 190
INF_SIZEOF_LLONG = 191
INF_CHANGE_COUNTER = 192 # database change counter; keeps track of byte and segment modifications
INF_SIZEOF_LDBL  = 196   # uchar;  sizeof(long double)

# Redefine these offsets for 64-bit version
if __EA64__:
    INF_CORESTART             = 25
    INF_OSTYPE                = 33
    INF_APPTYPE               = 35
    INF_START_SP              = 37
    INF_AF                    = 45
    INF_START_IP              = 47
    INF_BEGIN_EA              = 55
    INF_MIN_EA                = 63
    INF_MAX_EA                = 71
    INF_OMIN_EA               = 79
    INF_OMAX_EA               = 87
    INF_LOW_OFF               = 95
    INF_HIGH_OFF             = 103
    INF_MAXREF               = 111
    INF_ASCII_BREAK          = 119
    INF_WIDE_HIGH_BYTE_FIRST = 120
    INF_INDENT               = 121
    INF_COMMENT              = 122
    INF_XREFNUM              = 123
    INF_ENTAB                = 124
    INF_SPECSEGS             = 125
    INF_VOIDS                = 126
    INF_SHOWAUTO             = 128
    INF_AUTO                 = 129
    INF_BORDER               = 130
    INF_NULL                 = 131
    INF_GENFLAGS             = 132
    INF_SHOWPREF             = 133
    INF_PREFSEG              = 134
    INF_ASMTYPE              = 135
    INF_BASEADDR             = 136
    INF_XREFS                = 144
    INF_BINPREF              = 145
    INF_CMTFLAG              = 147
    INF_NAMETYPE             = 148
    INF_SHOWBADS             = 149
    INF_PREFFLAG             = 150
    INF_PACKBASE             = 151
    INF_ASCIIFLAGS           = 152
    INF_LISTNAMES            = 153
    INF_ASCIIPREF            = 154
    INF_ASCIISERNUM          = 170
    INF_ASCIIZEROES          = 178
    INF_MF                   = 182
    INF_ORG                  = 183
    INF_ASSUME               = 184
    INF_CHECKARG             = 185
    INF_START_SS             = 186
    INF_START_CS             = 194
    INF_MAIN                 = 202
    INF_SHORT_DN             = 210
    INF_LONG_DN              = 218
    INF_DATATYPES            = 226
    INF_STRTYPE              = 234
    INF_AF2                  = 242
    INF_NAMELEN              = 244
    INF_MARGIN               = 246
    INF_LENXREF              = 248
    INF_LPREFIX              = 250
    INF_LPREFIXLEN           = 266
    INF_COMPILER             = 267
    INF_MODEL                = 268
    INF_SIZEOF_INT           = 269
    INF_SIZEOF_BOOL          = 270
    INF_SIZEOF_ENUM          = 271
    INF_SIZEOF_ALGN          = 272
    INF_SIZEOF_SHORT         = 273
    INF_SIZEOF_LONG          = 274
    INF_SIZEOF_LLONG         = 275
    INF_CHANGE_COUNTER       = 276
    INF_SIZEOF_LBDL          = 280

_INFMAP = {
INF_VERSION     : (False, 'version'),      # short;   Version of database
INF_PROCNAME    : (False, 'procName'),     # char[8]; Name of current processor
INF_LFLAGS      : (False, 'lflags'),       # char;    IDP-dependent flags
INF_DEMNAMES    : (False, 'demnames'),     # char;    display demangled names as:
INF_FILETYPE    : (False, 'filetype'),     # short;   type of input file (see ida.hpp)
INF_FCORESIZ    : (False, 'fcoresize'),
INF_CORESTART   : (False, 'corestart'),
INF_OSTYPE      : (False, 'ostype'),       # short;   FLIRT: OS type the program is for
INF_APPTYPE     : (False, 'apptype'),      # short;   FLIRT: Application type
INF_START_SP    : (False, 'startSP'),      # long;    SP register value at the start of
INF_START_AF    : (False, 'af'),           # short;   Analysis flags:
INF_START_IP    : (False, 'startIP'),      # long;    IP register value at the start of
INF_BEGIN_EA    : (False, 'beginEA'),      # long;    Linear address of program entry point
INF_MIN_EA      : (False, 'minEA'),        # long;    The lowest address used
INF_MAX_EA      : (False, 'maxEA'),        # long;    The highest address used
INF_OMIN_EA     : (False, 'ominEA'),
INF_OMAX_EA     : (False, 'omaxEA'),
INF_LOW_OFF     : (False, 'lowoff'),       # long;    low limit of voids
INF_HIGH_OFF    : (False, 'highoff'),      # long;    high limit of voids
INF_MAXREF      : (False, 'maxref'),       # long;    max xref depth
INF_ASCII_BREAK : (False, 'ASCIIbreak'),   # char;    ASCII line break symbol
INF_WIDE_HIGH_BYTE_FIRST : (False, 'wide_high_byte_first'),
INF_INDENT      : (False, 'indent'),       # char;    Indention for instructions
INF_COMMENT     : (False, 'comment'),      # char;    Indention for comments
INF_XREFNUM     : (False, 'xrefnum'),      # char;    Number of references to generate
INF_ENTAB       : (False, 's_entab'),      # char;    Use '\t' chars in the output file?
INF_SPECSEGS    : (False, 'specsegs'),
INF_VOIDS       : (False, 's_void'),       # char;    Display void marks?
INF_SHOWAUTO    : (False, 's_showauto'),   # char;    Display autoanalysis indicator?
INF_AUTO        : (False, 's_auto'),       # char;    Autoanalysis is enabled?
INF_BORDER      : (False, 's_limiter'),    # char;    Generate borders?
INF_NULL        : (False, 's_null'),       # char;    Generate empty lines?
INF_GENFLAGS    : (False, 's_genflags'),   # char;    General flags:
INF_SHOWPREF    : (False, 's_showpref'),   # char;    Show line prefixes?
INF_PREFSEG     : (False, 's_prefseg'),    # char;    line prefixes with segment name?
INF_ASMTYPE     : (False, 'asmtype'),      # char;    target assembler number (0..n)
INF_BASEADDR    : (False, 'baseaddr'),     # long;    base paragraph of the program
INF_XREFS       : (False, 's_xrefflag'),   # char;    xrefs representation:
INF_BINPREF     : (False, 'binSize'),      # short;   # of instruction bytes to show
INF_CMTFLAG     : (False, 's_cmtflg'),     # char;    comments:
INF_NAMETYPE    : (False, 'nametype'),     # char;    dummy names represenation type
INF_SHOWBADS    : (False, 's_showbads'),   # char;    show bad instructions?
INF_PREFFLAG    : (False, 's_prefflag'),   # char;    line prefix type:
INF_PACKBASE    : (False, 's_packbase'),   # char;    pack database?
INF_ASCIIFLAGS  : (False, 'asciiflags'),   # uchar;   ascii flags
INF_LISTNAMES   : (False, 'listnames'),    # uchar;   What names should be included in the list?
INF_ASCIIPREF   : (False, 'ASCIIpref'),    # char[16];ASCII names prefix
INF_ASCIISERNUM : (False, 'ASCIIsernum'),  # ulong;   serial number
INF_ASCIIZEROES : (False, 'ASCIIzeroes'),  # char;    leading zeroes
INF_MF          : (False, 'mf'),           # uchar;   Byte order: 1==MSB first
INF_ORG         : (False, 's_org'),        # char;    Generate 'org' directives?
INF_ASSUME      : (False, 's_assume'),     # char;    Generate 'assume' directives?
INF_CHECKARG    : (False, 's_checkarg'),   # char;    Check manual operands?
INF_START_SS    : (False, 'start_ss'),     # long;    value of SS at the start
INF_START_CS    : (False, 'start_cs'),     # long;    value of CS at the start
INF_MAIN        : (False, 'main'),         # long;    address of main()
INF_SHORT_DN    : (False, 'short_demnames'), # long;    short form of demangled names
INF_LONG_DN     : (False, 'long_demnames'), # long;    long form of demangled names
INF_DATATYPES   : (False, 'datatypes'),    # long;    data types allowed in data carousel
INF_STRTYPE     : (False, 'strtype'),      # long;    current ascii string type
INF_AF2         : (False, 'af2'),          # ushort;  Analysis flags 2
INF_NAMELEN     : (False, 'namelen'),      # ushort;  max name length (without zero byte)
INF_MARGIN      : (False, 'margin'),       # ushort;  max length of data lines
INF_LENXREF     : (False, 'lenxref'),      # ushort;  max length of line with xrefs
INF_LPREFIX     : (False, 'lprefix'),      # char[16];prefix of local names
INF_LPREFIXLEN  : (False, 'lprefixlen'),   # uchar;   length of the lprefix
INF_COMPILER    : (False, 'cc')            # uchar;   compiler

#INF_MODEL       = 184             # uchar;   memory model & calling convention
#INF_SIZEOF_INT  = 185             # uchar;   sizeof(int)
#INF_SIZEOF_BOOL = 186             # uchar;   sizeof(bool)
#INF_SIZEOF_ENUM = 187             # uchar;   sizeof(enum)
#INF_SIZEOF_ALGN = 188             # uchar;   default alignment
#INF_SIZEOF_SHORT = 189
#INF_SIZEOF_LONG  = 190
#INF_SIZEOF_LLONG = 191
}


def SetProcessorType (processor, level):
    """
    Change current processor

    @param processor: name of processor in short form.
                      run 'ida ?' to get list of allowed processor types
    @param level: the power of request:
                  - SETPROC_COMPAT - search for the processor type in the current module
                  - SETPROC_ALL    - search for the processor type in all modules
                                     only if there were not calls with SETPROC_USER
                  - SETPROC_USER   - search for the processor type in all modules
                                     and prohibit level SETPROC_USER
                  - SETPROC_FATAL  - can be combined with previous bits.
                                     means that if the processor type can't be
                                     set, IDA should display an error message and exit.
    """
    return idaapi.set_processor_type(processor, level)

def SetTargetAssembler(asmidx):
    """
    Set target assembler
    @param asmidx: index of the target assembler in the array of
    assemblers for the current processor.

    @return: 1-ok, 0-failed
    """
    return idaapi.set_target_assembler(asmidx)

SETPROC_COMPAT = idaapi.SETPROC_COMPAT
SETPROC_ALL    = idaapi.SETPROC_ALL
SETPROC_USER   = idaapi.SETPROC_USER
SETPROC_FATAL  = idaapi.SETPROC_FATAL

def SetPrcsr(processor): return SetProcessorType(processor, SETPROC_COMPAT)


def Batch(batch):
    """
    Enable/disable batch mode of operation

    @param batch: Batch mode
            0 - ida will display dialog boxes and wait for the user input
            1 - ida will not display dialog boxes, warnings, etc.

    @return: old balue of batch flag
    """
    batch_prev = idaapi.cvar.batch
    idaapi.cvar.batch = batch
    return batch_prev


#----------------------------------------------------------------------------
#          I N T E R A C T I O N   W I T H   T H E   U S E R
#----------------------------------------------------------------------------
def AskStr(defval, prompt):
    """
    Ask the user to enter a string

    @param defval: the default string value. This value will appear
             in the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered string or None.
    """
    return idaapi.askstr(0, defval, prompt)


def AskFile(forsave, mask, prompt):
    """
    Ask the user to choose a file

    @param forsave: 0: "Open" dialog box, 1: "Save" dialog box
    @param mask: the input file mask as "*.*" or the default file name.
    @param prompt: the prompt to display in the dialog box

    @return: the selected file or None.
    """
    return idaapi.askfile_c(forsave, mask, prompt)


def AskAddr(defval, prompt):
    """
    Ask the user to enter an address

    @param defval: an ea_t designating the default address value. This value
             will appear in the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered address or BADADDR.
    """
    return idaapi.askaddr(defval, prompt)


def AskLong(defval, prompt):
    """
    Ask the user to enter a number

    @param defval: a number designating the default value. This value
             will appear in the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered number or -1.
    """
    return idaapi.asklong(defval, prompt)


def ProcessUiAction(name, flags=0):
    """
    Invokes an IDA UI action by name

    @param name: Command name
    @param flags: Reserved. Must be zero
    @return: Boolean
    """
    return idaapi.process_ui_action(name, flags)


def AskSeg(defval, prompt):
    """
    Ask the user to enter a segment value

    @param defval: the default value. This value
             will appear in the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered segment selector or BADSEL.
    """
    return idaapi.askseg(defval, prompt)


def AskIdent(defval, prompt):
    """
    Ask the user to enter an identifier

    @param defval: the default identifier. This value will appear in
             the dialog box.
    @param prompt: the prompt to display in the dialog box

    @return: the entered identifier or None.
    """
    return idaapi.askident(defval, prompt)


def AskYN(defval, prompt):
    """
    Ask the user a question and let him answer Yes/No/Cancel

    @param defval: the default answer. This answer will be selected if the user
            presses Enter. -1:cancel,0-no,1-ok
    @param prompt: the prompt to display in the dialog box

    @return: -1:cancel,0-no,1-ok
    """
    return idaapi.askyn_c(defval, prompt)


def Message(msg):
    """
    Display a message in the message window

    @param msg: message to print (formatting is done in Python)

    This function can be used to debug IDC scripts
    """
    idaapi.msg(msg)


def UMessage(msg):
    """
    Display an UTF-8 string in the message window

    The result of the stringification of the arguments
    will be treated as an UTF-8 string.

    @param msg: message to print (formatting is done in Python)

    This function can be used to debug IDC scripts
    """
    idaapi.umsg(msg)


def Warning(msg):
    """
    Display a message in a message box

    @param msg: message to print (formatting is done in Python)

    This function can be used to debug IDC scripts
    The user will be able to hide messages if they appear twice in a row on
    the screen
    """
    idaapi.warning(msg)


def Fatal(format):
    """
    Display a fatal message in a message box and quit IDA

    @param format: message to print
    """
    idaapi.error(format)


def SetStatus(status):
    """
    Change IDA indicator.

    @param status: new status

    @return: the previous status.
    """
    return idaapi.setStat(status)


IDA_STATUS_READY    = 0 # READY     IDA is idle
IDA_STATUS_THINKING = 1 # THINKING  Analyzing but the user may press keys
IDA_STATUS_WAITING  = 2 # WAITING   Waiting for the user input
IDA_STATUS_WORK     = 3 # BUSY      IDA is busy


def Refresh():
    """
    Refresh all disassembly views
    """
    idaapi.refresh_idaview_anyway()


def RefreshLists():
    """
    Refresh all list views (names, functions, etc)
    """
    idaapi.refresh_lists()


#----------------------------------------------------------------------------
#                        S E G M E N T A T I O N
#----------------------------------------------------------------------------
def AskSelector(sel):
    """
    Get a selector value

    @param sel: the selector number

    @return: selector value if found
             otherwise the input value (sel)

    @note: selector values are always in paragraphs
    """
    s = idaapi.sel_pointer()
    base = idaapi.ea_pointer()
    res,tmp = idaapi.getn_selector(sel, s.cast(), base.cast())

    if not res:
        return sel
    else:
        return base.value()


def FindSelector(val):
    """
    Find a selector which has the specifed value

    @param val: value to search for

    @return: the selector number if found,
             otherwise the input value (val & 0xFFFF)

    @note: selector values are always in paragraphs
    """
    return idaapi.find_selector(val) & 0xFFFF


def SetSelector(sel, value):
    """
    Set a selector value

    @param sel: the selector number
    @param value: value of selector

    @return: None

    @note: ida supports up to 4096 selectors.
            if 'sel' == 'val' then the selector is destroyed because
            it has no significance
    """
    return idaapi.set_selector(sel, value)


def DelSelector(sel):
    """
    Delete a selector

    @param sel: the selector number to delete

    @return: None

    @note: if the selector is found, it will be deleted
    """
    return idaapi.del_selector(sel)


def FirstSeg():
    """
    Get first segment

    @return: address of the start of the first segment
        BADADDR - no segments are defined
    """
    seg = idaapi.get_first_seg()
    if not seg:
        return BADADDR
    else:
        return seg.startEA


def NextSeg(ea):
    """
    Get next segment

    @param ea: linear address

    @return: start of the next segment
             BADADDR - no next segment
    """
    nextseg = idaapi.get_next_seg(ea)
    if not nextseg:
        return BADADDR
    else:
        return nextseg.startEA

    return BADADDR


def SegStart(ea):
    """
    Get start address of a segment

    @param ea: any address in the segment

    @return: start of segment
             BADADDR - the specified address doesn't belong to any segment
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return BADADDR
    else:
        return seg.startEA


def SegEnd(ea):
    """
    Get end address of a segment

    @param ea: any address in the segment

    @return: end of segment (an address past end of the segment)
             BADADDR - the specified address doesn't belong to any segment
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return BADADDR
    else:
        return seg.endEA


def SegName(ea):
    """
    Get name of a segment

    @param ea: any address in the segment

    @return: "" - no segment at the specified address
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return ""
    else:
        name = idaapi.get_true_segm_name(seg)

        if not name:
            return ""
        else:
            return name


def AddSegEx(startea, endea, base, use32, align, comb, flags):
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
    s = idaapi.segment_t()
    s.startEA     = startea
    s.endEA       = endea
    s.sel         = idaapi.setup_selector(base)
    s.bitness     = use32
    s.align       = align
    s.comb        = comb
    return idaapi.add_segm_ex(s, "", "", flags)

ADDSEG_NOSREG  = idaapi.ADDSEG_NOSREG  # set all default segment register values
                                       # to BADSELs
                                       # (undefine all default segment registers)
ADDSEG_OR_DIE  = idaapi. ADDSEG_OR_DIE # qexit() if can't add a segment
ADDSEG_NOTRUNC = idaapi.ADDSEG_NOTRUNC # don't truncate the new segment at the beginning
                                       # of the next segment if they overlap.
                                       # destroy/truncate old segments instead.
ADDSEG_QUIET   = idaapi.ADDSEG_QUIET   # silent mode, no "Adding segment..." in the messages window
ADDSEG_FILLGAP = idaapi.ADDSEG_FILLGAP # If there is a gap between the new segment
                                       # and the previous one, and this gap is less
                                       # than 64K, then fill the gap by extending the
                                       # previous segment and adding .align directive
                                       # to it. This way we avoid gaps between segments.
                                       # Too many gaps lead to a virtual array failure.
                                       # It can not hold more than ~1000 gaps.
ADDSEG_SPARSE  = idaapi.ADDSEG_SPARSE  # Use sparse storage method for the new segment

def AddSeg(startea, endea, base, use32, align, comb):
    return AddSegEx(startea, endea, base, use32, align, comb, ADDSEG_NOSREG)

def DelSeg(ea, flags):
    """
    Delete a segment

    @param ea: any address in the segment
    @param flags: combination of SEGMOD_* flags

    @return: boolean success
    """
    return idaapi.del_segm(ea, flags)

SEGMOD_KILL   = idaapi.SEGMOD_KILL   # disable addresses if segment gets
                                     # shrinked or deleted
SEGMOD_KEEP   = idaapi.SEGMOD_KEEP   # keep information (code & data, etc)
SEGMOD_SILENT = idaapi.SEGMOD_SILENT # be silent


def SetSegBounds(ea, startea, endea, flags):
    """
    Change segment boundaries

    @param ea: any address in the segment
    @param startea: new start address of the segment
    @param endea: new end address of the segment
    @param flags: combination of SEGMOD_... flags

    @return: boolean success
    """
    return idaapi.set_segm_start(ea, startea, flags) & \
           idaapi.set_segm_end(ea, endea, flags)


def RenameSeg(ea, name):
    """
    Change name of the segment

    @param ea: any address in the segment
    @param name: new name of the segment

    @return: success (boolean)
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return False

    return idaapi.set_segm_name(seg, name)


def SetSegClass(ea, segclass):
    """
    Change class of the segment

    @param ea: any address in the segment
    @param segclass: new class of the segment

    @return: success (boolean)
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return False

    return idaapi.set_segm_class(seg, segclass)


def SegAlign(ea, alignment):
    """
    Change alignment of the segment

    @param ea: any address in the segment
    @param alignment: new alignment of the segment (one of the sa... constants)

    @return: success (boolean)
    """
    return SetSegmentAttr(ea, SEGATTR_ALIGN, alignment)


saAbs        = idaapi.saAbs        # Absolute segment.
saRelByte    = idaapi.saRelByte    # Relocatable, byte aligned.
saRelWord    = idaapi.saRelWord    # Relocatable, word (2-byte, 16-bit) aligned.
saRelPara    = idaapi.saRelPara    # Relocatable, paragraph (16-byte) aligned.
saRelPage    = idaapi.saRelPage    # Relocatable, aligned on 256-byte boundary
                                   # (a "page" in the original Intel specification).
saRelDble    = idaapi.saRelDble    # Relocatable, aligned on a double word
                                   # (4-byte) boundary. This value is used by
                                   # the PharLap OMF for the same alignment.
saRel4K      = idaapi.saRel4K      # This value is used by the PharLap OMF for
                                   # page (4K) alignment. It is not supported
                                   # by LINK.
saGroup      = idaapi.saGroup      # Segment group
saRel32Bytes = idaapi.saRel32Bytes # 32 bytes
saRel64Bytes = idaapi.saRel64Bytes # 64 bytes
saRelQword   = idaapi.saRelQword   # 8 bytes


def SegComb(segea, comb):
    """
    Change combination of the segment

    @param segea: any address in the segment
    @param comb: new combination of the segment (one of the sc... constants)

    @return: success (boolean)
    """
    return SetSegmentAttr(segea, SEGATTR_COMB, comb)


scPriv   = idaapi.scPriv   # Private. Do not combine with any other program
                           # segment.
scPub    = idaapi.scPub    # Public. Combine by appending at an offset that
                           # meets the alignment requirement.
scPub2   = idaapi.scPub2   # As defined by Microsoft, same as C=2 (public).
scStack  = idaapi.scStack  # Stack. Combine as for C=2. This combine type
                           # forces byte alignment.
scCommon = idaapi.scCommon # Common. Combine by overlay using maximum size.
scPub3   = idaapi.scPub3   # As defined by Microsoft, same as C=2 (public).


def SetSegAddressing(ea, bitness):
    """
    Change segment addressing

    @param ea: any address in the segment
    @param bitness: 0: 16bit, 1: 32bit, 2: 64bit

    @return: success (boolean)
    """
    seg = idaapi.getseg(ea)

    if not seg:
        return False

    seg.bitness = bitness

    return True


def SegByName(segname):
    """
    Get segment by name

    @param segname: name of segment

    @return: segment selector or BADADDR
    """
    seg = idaapi.get_segm_by_name(segname)

    if not seg:
        return BADADDR

    return seg.sel


def SetSegDefReg(ea, reg, value):
    """
    Set default segment register value for a segment

    @param ea: any address in the segment
               if no segment is present at the specified address
               then all segments will be affected
    @param reg: name of segment register
    @param value: default value of the segment register. -1-undefined.
    """
    seg = idaapi.getseg(ea)

    reg = idaapi.str2reg(reg);
    if seg and reg >= 0:
        return idaapi.SetDefaultRegisterValue(seg, reg, value)
    else:
        return False


def SetSegmentType(segea, segtype):
    """
    Set segment type

    @param segea: any address within segment
    @param segtype: new segment type:

    @return: !=0 - ok
    """
    seg = idaapi.getseg(segea)

    if not seg:
        return False

    seg.type = segtype
    return seg.update()


SEG_NORM   = idaapi.SEG_NORM
SEG_XTRN   = idaapi.SEG_XTRN   # * segment with 'extern' definitions
                               #   no instructions are allowed
SEG_CODE   = idaapi.SEG_CODE   # pure code segment
SEG_DATA   = idaapi.SEG_DATA   # pure data segment
SEG_IMP    = idaapi.SEG_IMP    # implementation segment
SEG_GRP    = idaapi.SEG_GRP    # * group of segments
                               #   no instructions are allowed
SEG_NULL   = idaapi.SEG_NULL   # zero-length segment
SEG_UNDF   = idaapi.SEG_UNDF   # undefined segment type
SEG_BSS    = idaapi.SEG_BSS    # uninitialized segment
SEG_ABSSYM = idaapi.SEG_ABSSYM # * segment with definitions of absolute symbols
                               #   no instructions are allowed
SEG_COMM   = idaapi.SEG_COMM   # * segment with communal definitions
                               #   no instructions are allowed
SEG_IMEM   = idaapi.SEG_IMEM   # internal processor memory & sfr (8051)


def GetSegmentAttr(segea, attr):
    """
    Get segment attribute

    @param segea: any address within segment
    @param attr: one of SEGATTR_... constants
    """
    seg = idaapi.getseg(segea)
    assert seg, "could not find segment at 0x%x" % segea
    if attr in [ SEGATTR_ES, SEGATTR_CS, SEGATTR_SS, SEGATTR_DS, SEGATTR_FS, SEGATTR_GS ]:
        return idaapi.get_defsr(seg, _SEGATTRMAP[attr][1])
    else:
        return _IDC_GetAttr(seg, _SEGATTRMAP, attr)


def SetSegmentAttr(segea, attr, value):
    """
    Set segment attribute

    @param segea: any address within segment
    @param attr: one of SEGATTR_... constants

    @note: Please note that not all segment attributes are modifiable.
           Also some of them should be modified using special functions
           like SetSegAddressing, etc.
    """
    seg = idaapi.getseg(segea)
    assert seg, "could not find segment at 0x%x" % segea
    if attr in [ SEGATTR_ES, SEGATTR_CS, SEGATTR_SS, SEGATTR_DS, SEGATTR_FS, SEGATTR_GS ]:
        idaapi.set_defsr(seg, _SEGATTRMAP[attr][1], value)
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
                          #       Using SetSegAddressing() is more correct.
SEGATTR_FLAGS   = 24      # segment flags
SEGATTR_SEL     = 26      # segment selector
SEGATTR_ES      = 30      # default ES value
SEGATTR_CS      = 34      # default CS value
SEGATTR_SS      = 38      # default SS value
SEGATTR_DS      = 42      # default DS value
SEGATTR_FS      = 46      # default FS value
SEGATTR_GS      = 50      # default GS value
SEGATTR_TYPE    = 94      # segment type
SEGATTR_COLOR   = 95      # segment color

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
    SEGATTR_SEL     = 46
    SEGATTR_ES      = 54
    SEGATTR_CS      = 62
    SEGATTR_SS      = 70
    SEGATTR_DS      = 78
    SEGATTR_FS      = 86
    SEGATTR_GS      = 94
    SEGATTR_TYPE    = 182
    SEGATTR_COLOR   = 183

_SEGATTRMAP = {
    SEGATTR_START   : (True, 'startEA'),
    SEGATTR_END     : (True, 'endEA'),
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


def MoveSegm(ea, to, flags):
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
    seg = idaapi.getseg(ea)
    if not seg:
        return MOVE_SEGM_PARAM
    return idaapi.move_segm(seg, to, flags)


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
    return idaapi.rebase_program(delta, flags)


def SetStorageType(startEA, endEA, stt):
    """
    Set storage type

    @param startEA: starting address
    @param endEA: ending address
    @param stt: new storage type, one of STT_VA and STT_MM

    @returns: 0 - ok, otherwise internal error code
    """
    return idaapi.change_storage_type(startEA, endEA, stt)


STT_VA = 0  # regular storage: virtual arrays, an explicit flag for each byte
STT_MM = 1  # memory map: sparse storage. useful for huge objects


#----------------------------------------------------------------------------
#                    C R O S S   R E F E R E N C E S
#----------------------------------------------------------------------------
#      Flow types (combine with XREF_USER!):
fl_CF   = 16              # Call Far
fl_CN   = 17              # Call Near
fl_JF   = 18              # Jump Far
fl_JN   = 19              # Jump Near
fl_F    = 21              # Ordinary flow

XREF_USER = 32            # All user-specified xref types
                          # must be combined with this bit


# Mark exec flow 'from' 'to'
def AddCodeXref(From, To, flowtype):
    """
    """
    return idaapi.add_cref(From, To, flowtype)


def DelCodeXref(From, To, undef):
    """
    Unmark exec flow 'from' 'to'

    @param undef: make 'To' undefined if no more references to it

    @returns: 1 - planned to be made undefined
    """
    return idaapi.del_cref(From, To, undef)


# The following functions include the ordinary flows:
# (the ordinary flow references are returned first)
def Rfirst(From):
    """
    Get first code xref from 'From'
    """
    return idaapi.get_first_cref_from(From)


def Rnext(From, current):
    """
    Get next code xref from
    """
    return idaapi.get_next_cref_from(From, current)


def RfirstB(To):
    """
    Get first code xref to 'To'
    """
    return idaapi.get_first_cref_to(To)


def RnextB(To, current):
    """
    Get next code xref to 'To'
    """
    return idaapi.get_next_cref_to(To, current)


# The following functions don't take into account the ordinary flows:
def Rfirst0(From):
    """
    Get first xref from 'From'
    """
    return idaapi.get_first_fcref_from(From)


def Rnext0(From, current):
    """
    Get next xref from
    """
    return idaapi.get_next_fcref_from(From, current)


def RfirstB0(To):
    """
    Get first xref to 'To'
    """
    return idaapi.get_first_fcref_to(To)


def RnextB0(To, current):
    """
    Get next xref to 'To'
    """
    return idaapi.get_next_fcref_to(To, current)


# Data reference types (combine with XREF_USER!):
dr_O    = idaapi.dr_O  # Offset
dr_W    = idaapi.dr_W  # Write
dr_R    = idaapi.dr_R  # Read
dr_T    = idaapi.dr_T  # Text (names in manual operands)
dr_I    = idaapi.dr_I  # Informational


def add_dref(From, To, drefType):
    """
    Create Data Ref
    """
    return idaapi.add_dref(From, To, drefType)


def del_dref(From, To):
    """
    Unmark Data Ref
    """
    return idaapi.del_dref(From, To)


def Dfirst(From):
    """
    Get first data xref from 'From'
    """
    return idaapi.get_first_dref_from(From)


def Dnext(From, current):
    """
    Get next data xref from 'From'
    """
    return idaapi.get_next_dref_from(From, current)


def DfirstB(To):
    """
    Get first data xref to 'To'
    """
    return idaapi.get_first_dref_to(To)


def DnextB(To, current):
    """
    Get next data xref to 'To'
    """
    return idaapi.get_next_dref_to(To, current)


def XrefType():
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
    li = idaapi.open_linput(filepath, False)

    if li:
        retval = idaapi.file2base(li, pos, ea, ea+size, False)
        idaapi.close_linput(li)
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
        of = idaapi.fopenM(filepath)
    else:
        of = idaapi.fopenWB(filepath)


    if of:
        retval = idaapi.base2file(of, pos, ea, ea+size)
        idaapi.eclose(of)
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

def MakeFunction(start, end = idaapi.BADADDR):
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
    return idaapi.add_func(start, end)


def DelFunction(ea):
    """
    Delete a function

    @param ea: any address belonging to the function

    @return: !=0 - ok
    """
    return idaapi.del_func(ea)


def SetFunctionEnd(ea, end):
    """
    Change function end address

    @param ea: any address belonging to the function
    @param end: new function end address

    @return: !=0 - ok
    """
    return idaapi.func_setend(ea, end)


def NextFunction(ea):
    """
    Find next function

    @param ea: any address belonging to the function

    @return:        BADADDR - no more functions
            otherwise returns the next function start address
    """
    func = idaapi.get_next_func(ea)

    if not func:
        return BADADDR
    else:
        return func.startEA


def PrevFunction(ea):
    """
    Find previous function

    @param ea: any address belonging to the function

    @return: BADADDR - no more functions
            otherwise returns the previous function start address
    """
    func = idaapi.get_prev_func(ea)

    if not func:
        return BADADDR
    else:
        return func.startEA


def GetFunctionAttr(ea, attr):
    """
    Get a function attribute

    @param ea: any address belonging to the function
    @param attr: one of FUNCATTR_... constants

    @return: BADADDR - error otherwise returns the attribute value
    """
    func = idaapi.get_func(ea)

    return _IDC_GetAttr(func, _FUNCATTRMAP, attr) if func else BADADDR


def SetFunctionAttr(ea, attr, value):
    """
    Set a function attribute

    @param ea: any address belonging to the function
    @param attr: one of FUNCATTR_... constants
    @param value: new value of the attribute

    @return: 1-ok, 0-failed
    """
    func = idaapi.get_func(ea)

    if func:
        _IDC_SetAttr(func, _FUNCATTRMAP, attr, value)
        return idaapi.update_func(func)
    return 0


FUNCATTR_START   =  0     # function start address
FUNCATTR_END     =  4     # function end address
FUNCATTR_FLAGS   =  8     # function flags
FUNCATTR_FRAME   = 10     # function frame id
FUNCATTR_FRSIZE  = 14     # size of local variables
FUNCATTR_FRREGS  = 18     # size of saved registers area
FUNCATTR_ARGSIZE = 20     # number of bytes purged from the stack
FUNCATTR_FPD     = 24     # frame pointer delta
FUNCATTR_COLOR   = 28     # function color code
FUNCATTR_OWNER   = 10     # chunk owner (valid only for tail chunks)
FUNCATTR_REFQTY  = 14     # number of chunk parents (valid only for tail chunks)

# Redefining the constants for 64-bit
if __EA64__:
    FUNCATTR_START   = 0
    FUNCATTR_END     = 8
    FUNCATTR_FLAGS   = 16
    FUNCATTR_FRAME   = 18
    FUNCATTR_FRSIZE  = 26
    FUNCATTR_FRREGS  = 34
    FUNCATTR_ARGSIZE = 36
    FUNCATTR_FPD     = 44
    FUNCATTR_COLOR   = 52
    FUNCATTR_OWNER   = 18
    FUNCATTR_REFQTY  = 26


_FUNCATTRMAP = {
    FUNCATTR_START   : (True, 'startEA'),
    FUNCATTR_END     : (True, 'endEA'),
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


def GetFunctionFlags(ea):
    """
    Retrieve function flags

    @param ea: any address belonging to the function

    @return: -1 - function doesn't exist otherwise returns the flags
    """
    func = idaapi.get_func(ea)

    if not func:
        return -1
    else:
        return func.flags


FUNC_NORET         = idaapi.FUNC_NORET         # function doesn't return
FUNC_FAR           = idaapi.FUNC_FAR           # far function
FUNC_LIB           = idaapi.FUNC_LIB           # library function
FUNC_STATIC        = idaapi.FUNC_STATICDEF     # static function
FUNC_FRAME         = idaapi.FUNC_FRAME         # function uses frame pointer (BP)
FUNC_USERFAR       = idaapi.FUNC_USERFAR       # user has specified far-ness
                                               # of the function
FUNC_HIDDEN        = idaapi.FUNC_HIDDEN        # a hidden function
FUNC_THUNK         = idaapi.FUNC_THUNK         # thunk (jump) function
FUNC_BOTTOMBP      = idaapi.FUNC_BOTTOMBP      # BP points to the bottom of the stack frame
FUNC_NORET_PENDING = idaapi.FUNC_NORET_PENDING # Function 'non-return' analysis
                                               # must be performed. This flag is
                                               # verified upon func_does_return()
FUNC_SP_READY      = idaapi.FUNC_SP_READY      # SP-analysis has been performed
                                               # If this flag is on, the stack
                                               # change points should not be not
                                               # modified anymore. Currently this
                                               # analysis is performed only for PC
FUNC_PURGED_OK     = idaapi.FUNC_PURGED_OK     # 'argsize' field has been validated.
                                               # If this bit is clear and 'argsize'
                                               # is 0, then we do not known the real
                                               # number of bytes removed from
                                               # the stack. This bit is handled
                                               # by the processor module.
FUNC_TAIL          = idaapi.FUNC_TAIL          # This is a function tail.
                                               # Other bits must be clear
                                               # (except FUNC_HIDDEN)


def SetFunctionFlags(ea, flags):
    """
    Change function flags

    @param ea: any address belonging to the function
    @param flags: see GetFunctionFlags() for explanations

    @return: !=0 - ok
    """
    func = idaapi.get_func(ea)

    if not func:
        return 0
    else:
        func.flags = flags
        idaapi.update_func(func)
        return 1


def GetFunctionName(ea):
    """
    Retrieve function name

    @param ea: any address belonging to the function

    @return: null string - function doesn't exist
            otherwise returns function name
    """
    name = idaapi.get_func_name(ea)

    if not name:
        return ""
    else:
        return name


def GetFunctionCmt(ea, repeatable):
    """
    Retrieve function comment

    @param ea: any address belonging to the function
    @param repeatable: 1: get repeatable comment
            0: get regular comment

    @return: function comment string
    """
    func = idaapi.get_func(ea)

    if not func:
        return ""
    else:
        comment = idaapi.get_func_cmt(func, repeatable)

        if not comment:
            return ""
        else:
            return comment


def SetFunctionCmt(ea, cmt, repeatable):
    """
    Set function comment

    @param ea: any address belonging to the function
    @param cmt: a function comment line
    @param repeatable: 1: get repeatable comment
            0: get regular comment
    """
    func = idaapi.get_func(ea)

    if not func:
        return None
    else:
        return idaapi.set_func_cmt(func, cmt, repeatable)


def ChooseFunction(title):
    """
    Ask the user to select a function

    Arguments:

    @param title: title of the dialog box

    @return: -1 - user refused to select a function
             otherwise returns the selected function start address
    """
    f = idaapi.choose_func(title, idaapi.BADADDR)
    return BADADDR if f is None else f.startEA


def GetFuncOffset(ea):
    """
    Convert address to 'funcname+offset' string

    @param ea: address to convert

    @return: if the address belongs to a function then return a string
             formed as 'name+offset' where 'name' is a function name
             'offset' is offset within the function else return null string
    """
    return idaapi.a2funcoff(ea)


def FindFuncEnd(ea):
    """
    Determine a new function boundaries

    @param ea: starting address of a new function

    @return: if a function already exists, then return its end address.
            If a function end cannot be determined, the return BADADDR
            otherwise return the end address of the new function
    """
    func = idaapi.func_t()

    res = idaapi.find_func_bounds(ea, func, idaapi.FIND_FUNC_DEFINE)

    if res == idaapi.FIND_FUNC_UNDEF:
        return BADADDR
    else:
        return func.endEA


def GetFrame(ea):
    """
    Get ID of function frame structure

    @param ea: any address belonging to the function

    @return: ID of function frame or None In order to access stack variables
             you need to use structure member manipulaion functions with the
             obtained ID.
    """
    frame = idaapi.get_frame(ea)

    if frame:
        return frame.id
    else:
        return None


def GetFrameLvarSize(ea):
    """
    Get size of local variables in function frame

    @param ea: any address belonging to the function

    @return: Size of local variables in bytes.
             If the function doesn't have a frame, return 0
             If the function does't exist, return None
    """
    return GetFunctionAttr(ea, FUNCATTR_FRSIZE)


def GetFrameRegsSize(ea):
    """
    Get size of saved registers in function frame

    @param ea: any address belonging to the function

    @return: Size of saved registers in bytes.
             If the function doesn't have a frame, return 0
             This value is used as offset for BP (if FUNC_FRAME is set)
             If the function does't exist, return None
    """
    return GetFunctionAttr(ea, FUNCATTR_FRREGS)


def GetFrameArgsSize(ea):
    """
    Get size of arguments in function frame which are purged upon return

    @param ea: any address belonging to the function

    @return: Size of function arguments in bytes.
             If the function doesn't have a frame, return 0
             If the function does't exist, return -1
    """
    return GetFunctionAttr(ea, FUNCATTR_ARGSIZE)


def GetFrameSize(ea):
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
    func = idaapi.get_func(ea)

    if not func:
        return 0
    else:
        return idaapi.get_frame_size(func)


def MakeFrame(ea, lvsize, frregs, argsize):
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
    func = idaapi.get_func(ea)
    if func is None:
        return -1

    frameid = idaapi.add_frame(func, lvsize, frregs, argsize)

    if not frameid:
        if not idaapi.set_frame_size(func, lvsize, frregs, argsize):
            return -1

    return func.frame


def GetSpd(ea):
    """
    Get current delta for the stack pointer

    @param ea: end address of the instruction
               i.e.the last address of the instruction+1

    @return: The difference between the original SP upon
             entering the function and SP for the specified address
    """
    func = idaapi.get_func(ea)

    if not func:
        return None

    return idaapi.get_spd(func, ea)


def GetSpDiff(ea):
    """
    Get modification of SP made by the instruction

    @param ea: end address of the instruction
               i.e.the last address of the instruction+1

    @return: Get modification of SP made at the specified location
             If the specified location doesn't contain a SP change point, return 0
             Otherwise return delta of SP modification
    """
    func = idaapi.get_func(ea)

    if not func:
        return None

    return idaapi.get_sp_delta(func, ea)


def SetSpDiff(ea, delta):
    """
    Setup modification of SP made by the instruction

    @param ea: end address of the instruction
               i.e.the last address of the instruction+1
    @param delta: the difference made by the current instruction.

    @return: 1-ok, 0-failed
    """
    return idaapi.add_user_stkpnt(ea, delta)


# ----------------------------------------------------------------------------
#                              S T A C K
# ----------------------------------------------------------------------------

def AddAutoStkPnt2(func_ea, ea, delta):
    """
    Add automatical SP register change point
    @param func_ea: function start
    @param ea: linear address where SP changes
               usually this is the end of the instruction which
               modifies the stack pointer (cmd.ea+cmd.size)
    @param delta: difference between old and new values of SP
    @return: 1-ok, 0-failed
    """
    pfn = idaapi.get_func(func_ea)
    if not pfn:
        return 0
    return idaapi.add_auto_stkpnt2(pfn, ea, delta)

def AddUserStkPnt(ea, delta):
    """
    Add user-defined SP register change point.

    @param ea: linear address where SP changes
    @param delta: difference between old and new values of SP

    @return: 1-ok, 0-failed
    """
    return idaapi.add_user_stkpnt(ea, delta);

def DelStkPnt(func_ea, ea):
    """
    Delete SP register change point

    @param func_ea: function start
    @param ea: linear address
    @return: 1-ok, 0-failed
    """
    pfn = idaapi.get_func(func_ea)
    if not pfn:
        return 0
    return idaapi.del_stkpnt(pfn, ea)

def GetMinSpd(func_ea):
    """
    Return the address with the minimal spd (stack pointer delta)
    If there are no SP change points, then return BADADDR.

    @param func_ea: function start
    @return: BADDADDR - no such function
    """
    pfn = idaapi.get_func(func_ea)
    if not pfn:
        return BADADDR
    return idaapi.get_min_spd_ea(pfn)

def RecalcSpd(cur_ea):
    """
    Recalculate SP delta for an instruction that stops execution.

    @param cur_ea: linear address of the current instruction
    @return: 1 - new stkpnt is added, 0 - nothing is changed
    """
    return idaapi.recalc_spd(cur_ea)





# ----------------------------------------------------------------------------
#                        E N T R Y   P O I N T S
# ----------------------------------------------------------------------------

def GetEntryPointQty():
    """
    Retrieve number of entry points

    @returns: number of entry points
    """
    return idaapi.get_entry_qty()


def AddEntryPoint(ordinal, ea, name, makecode):
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
    return idaapi.add_entry(ordinal, ea, name, makecode)


def GetEntryOrdinal(index):
    """
    Retrieve entry point ordinal number

    @param index: 0..GetEntryPointQty()-1

    @return: 0 if entry point doesn't exist
            otherwise entry point ordinal
    """
    return idaapi.get_entry_ordinal(index)


def GetEntryPoint(ordinal):
    """
    Retrieve entry point address

    @param ordinal: entry point number
        it is returned by GetEntryPointOrdinal()

    @return: BADADDR if entry point doesn't exist
            otherwise entry point address.
            If entry point address is equal to its ordinal
            number, then the entry point has no ordinal.
    """
    return idaapi.get_entry(ordinal)


def GetEntryName(ordinal):
    """
    Retrieve entry point name

    @param ordinal: entry point number, ass returned by GetEntryPointOrdinal()

    @return: entry point name or None
    """
    return idaapi.get_entry_name(ordinal)


def RenameEntryPoint(ordinal, name):
    """
    Rename entry point

    @param ordinal: entry point number
    @param name: new name

    @return: !=0 - ok
    """
    return idaapi.rename_entry(ordinal, name)


# ----------------------------------------------------------------------------
#                              F I X U P S
# ----------------------------------------------------------------------------
def GetNextFixupEA(ea):
    """
    Find next address with fixup information

    @param ea: current address

    @return: BADADDR - no more fixups otherwise returns the next
                address with fixup information
    """
    return idaapi.get_next_fixup_ea(ea)


def GetPrevFixupEA(ea):
    """
    Find previous address with fixup information

    @param ea: current address

    @return: BADADDR - no more fixups otherwise returns the
                previous address with fixup information
    """
    return idaapi.get_prev_fixup_ea(ea)


def GetFixupTgtType(ea):
    """
    Get fixup target type

    @param ea: address to get information about

    @return: -1 - no fixup at the specified address
                otherwise returns fixup target type:
    """
    fd = idaapi.fixup_data_t()

    if not idaapi.get_fixup(ea, fd):
        return -1

    return fd.type


FIXUP_MASK      = 0xF
FIXUP_OFF8      = 0       # 8-bit offset.
FIXUP_BYTE      = FIXUP_OFF8 # 8-bit offset.
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
FIXUP_REL       = 0x10    # fixup is relative to the linear address
                          # specified in the 3d parameter to set_fixup()
FIXUP_SELFREL   = 0x0     # self-relative?
                          #   - disallows the kernel to convert operands
                          #      in the first pass
                          #   - this fixup is used during output
                          # This type of fixups is not used anymore.
                          # Anyway you can use it for commenting purposes
                          # in the loader modules
FIXUP_EXTDEF    = 0x20    # target is a location (otherwise - segment)
FIXUP_UNUSED    = 0x40    # fixup is ignored by IDA
                          #   - disallows the kernel to convert operands
                          #   - this fixup is not used during output
FIXUP_CREATED   = 0x80    # fixup was not present in the input file


def GetFixupTgtSel(ea):
    """
    Get fixup target selector

    @param ea: address to get information about

    @return: -1 - no fixup at the specified address
                    otherwise returns fixup target selector
    """
    fd = idaapi.fixup_data_t()

    if not idaapi.get_fixup(ea, fd):
        return -1

    return fd.sel


def GetFixupTgtOff(ea):
    """
    Get fixup target offset

    @param ea: address to get information about

    @return: -1 - no fixup at the specified address
                otherwise returns fixup target offset
    """
    fd = idaapi.fixup_data_t()

    if not idaapi.get_fixup(ea, fd):
        return -1

    return fd.off


def GetFixupTgtDispl(ea):
    """
    Get fixup target displacement

    @param ea: address to get information about

    @return: -1 - no fixup at the specified address
                otherwise returns fixup target displacement
    """
    fd = idaapi.fixup_data_t()

    if not idaapi.get_fixup(ea, fd):
        return -1

    return fd.displacement


def SetFixup(ea, fixuptype, targetsel, targetoff, displ):
    """
    Set fixup information

    @param ea: address to set fixup information about
    @param fixuptype: fixup type. see GetFixupTgtType()
                      for possible fixup types.
    @param targetsel: target selector
    @param targetoff: target offset
    @param displ: displacement

    @return:        none
    """
    fd = idaapi.fixup_data_t()
    fd.type = fixuptype
    fd.sel  = targetsel
    fd.off  = targetoff
    fd.displacement = displ

    idaapi.set_fixup(ea, fd)


def DelFixup(ea):
    """
    Delete fixup information

    @param ea: address to delete fixup information about

    @return: None
    """
    idaapi.del_fixup(ea)


#----------------------------------------------------------------------------
#                   M A R K E D   P O S I T I O N S
#----------------------------------------------------------------------------

def MarkPosition(ea, lnnum, x, y, slot, comment):
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
    curloc = idaapi.curloc()
    curloc.ea = ea
    curloc.lnnum = lnnum
    curloc.x = x
    curloc.y = y
    curloc.mark(slot, comment, comment)


def GetMarkedPos(slot):
    """
    Get marked position

    @param slot: slot number: 1..1024 if the specifed value is <= 0
                 range, IDA will ask the user to select slot.

    @return: BADADDR - the slot doesn't contain a marked address
             otherwise returns the marked address
    """
    curloc = idaapi.curloc()
    intp = idaapi.int_pointer()
    intp.assign(slot)
    return curloc.markedpos(intp)


def GetMarkComment(slot):
    """
    Get marked position comment

    @param slot: slot number: 1..1024

    @return: None if the slot doesn't contain a marked address
             otherwise returns the marked address comment
    """
    curloc = idaapi.curloc()
    return curloc.markdesc(slot)


# ----------------------------------------------------------------------------
#                          S T R U C T U R E S
# ----------------------------------------------------------------------------

def GetStrucQty():
    """
    Get number of defined structure types

    @return: number of structure types
    """
    return idaapi.get_struc_qty()


def GetFirstStrucIdx():
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
    return idaapi.get_first_struc_idx()


def GetLastStrucIdx():
    """
    Get index of last structure type

    @return:        BADADDR if no structure type is defined
                    index of last structure type.
                    See GetFirstStrucIdx() for the explanation of
                    structure indices and IDs.
    """
    return idaapi.get_last_struc_idx()


def GetNextStrucIdx(index):
    """
    Get index of next structure type

    @param index: current structure index

    @return:    BADADDR if no (more) structure type is defined
                index of the next structure type.
                See GetFirstStrucIdx() for the explanation of
                structure indices and IDs.
    """
    return idaapi.get_next_struc_idx(index)


def GetPrevStrucIdx(index):
    """
    Get index of previous structure type

    @param index: current structure index

    @return:    BADADDR if no (more) structure type is defined
                index of the presiouvs structure type.
                See GetFirstStrucIdx() for the explanation of
                structure indices and IDs.
    """
    return idaapi.get_prev_struc_idx(index)


def GetStrucIdx(sid):
    """
    Get structure index by structure ID

    @param sid: structure ID

    @return:    BADADDR if bad structure ID is passed
                otherwise returns structure index.
                See GetFirstStrucIdx() for the explanation of
                structure indices and IDs.
    """
    return idaapi.get_struc_idx(sid)


def GetStrucId(index):
    """
    Get structure ID by structure index

    @param index: structure index

    @return: BADADDR if bad structure index is passed otherwise returns structure ID.

    @note: See GetFirstStrucIdx() for the explanation of structure indices and IDs.
    """
    return idaapi.get_struc_by_idx(index)


def GetStrucIdByName(name):
    """
    Get structure ID by structure name

    @param name: structure type name

    @return:    BADADDR if bad structure type name is passed
                otherwise returns structure ID.
    """
    return idaapi.get_struc_id(name)


def GetStrucName(sid):
    """
    Get structure type name

    @param sid: structure type ID

    @return:    None if bad structure type ID is passed
                otherwise returns structure type name.
    """
    return idaapi.get_struc_name(sid)


def GetStrucComment(sid, repeatable):
    """
    Get structure type comment

    @param sid: structure type ID
    @param repeatable: 1: get repeatable comment
                0: get regular comment

    @return: None if bad structure type ID is passed
                otherwise returns comment.
    """
    return idaapi.get_struc_cmt(sid, repeatable)


def GetStrucSize(sid):
    """
    Get size of a structure

    @param sid: structure type ID

    @return:    0 if bad structure type ID is passed
                otherwise returns size of structure in bytes.
    """
    return idaapi.get_struc_size(sid)


def GetMemberQty(sid):
    """
    Get number of members of a structure

    @param sid: structure type ID

    @return: -1 if bad structure type ID is passed otherwise
             returns number of members.

    @note: Union members are, in IDA's internals, located
           at subsequent byte offsets: member 0 -> offset 0x0,
           member 1 -> offset 0x1, etc...
    """
    s = idaapi.get_struc(sid)
    return -1 if not s else s.memqty


def GetMemberId(sid, member_offset):
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
    s = idaapi.get_struc(sid)
    if not s:
        return -1

    m = idaapi.get_member(s, member_offset)
    if not m:
        return -1

    return m.id


def GetStrucPrevOff(sid, offset):
    """
    Get previous offset in a structure

    @param sid: structure type ID
    @param offset: current offset

    @return: -1 if bad structure type ID is passed,
             idaapi.BADADDR if no (more) offsets in the structure,
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
    s = idaapi.get_struc(sid)
    if not s:
        return -1

    return idaapi.get_struc_prev_offset(s, offset)


def GetStrucNextOff(sid, offset):
    """
    Get next offset in a structure

    @param sid:     structure type ID
    @param offset: current offset

    @return: -1 if bad structure type ID is passed,
             idaapi.BADADDR if no (more) offsets in the structure,
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
    s = idaapi.get_struc(sid)
    return -1 if not s else idaapi.get_struc_next_offset(s, offset)


def GetFirstMember(sid):
    """
    Get offset of the first member of a structure

    @param sid: structure type ID

    @return: -1 if bad structure type ID is passed,
             idaapi.BADADDR if structure has no members,
             otherwise returns offset of the first member.

    @note: IDA allows 'holes' between members of a
           structure. It treats these 'holes'
           as unnamed arrays of bytes.

    @note: Union members are, in IDA's internals, located
           at subsequent byte offsets: member 0 -> offset 0x0,
           member 1 -> offset 0x1, etc...
    """
    s = idaapi.get_struc(sid)
    if not s:
        return -1

    return idaapi.get_struc_first_offset(s)


def GetLastMember(sid):
    """
    Get offset of the last member of a structure

    @param sid: structure type ID

    @return: -1 if bad structure type ID is passed,
             idaapi.BADADDR if structure has no members,
             otherwise returns offset of the last member.

    @note: IDA allows 'holes' between members of a
          structure. It treats these 'holes'
          as unnamed arrays of bytes.

    @note: Union members are, in IDA's internals, located
           at subsequent byte offsets: member 0 -> offset 0x0,
           member 1 -> offset 0x1, etc...
    """
    s = idaapi.get_struc(sid)
    if not s:
        return -1

    return idaapi.get_struc_last_offset(s)


def GetMemberOffset(sid, member_name):
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
    s = idaapi.get_struc(sid)
    if not s:
        return -1

    m = idaapi.get_member_by_name(s, member_name)
    if not m:
        return -1

    return m.get_soff()


def GetMemberName(sid, member_offset):
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
    s = idaapi.get_struc(sid)
    if not s:
        return None

    m = idaapi.get_member(s, member_offset)
    if not m:
        return None

    return idaapi.get_member_name(m.id)


def GetMemberComment(sid, member_offset, repeatable):
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
    s = idaapi.get_struc(sid)
    if not s:
        return None

    m = idaapi.get_member(s, member_offset)
    if not m:
        return None

    return idaapi.get_member_cmt(m.id, repeatable)


def GetMemberSize(sid, member_offset):
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
    s = idaapi.get_struc(sid)
    if not s:
        return None

    m = idaapi.get_member(s, member_offset)
    if not m:
        return None

    return idaapi.get_member_size(m)


def GetMemberFlag(sid, member_offset):
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
    s = idaapi.get_struc(sid)
    if not s:
        return -1

    m = idaapi.get_member(s, member_offset)
    return -1 if not m else m.flag


def GetMemberStrId(sid, member_offset):
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
    s = idaapi.get_struc(sid)
    if not s:
        return -1

    m = idaapi.get_member(s, member_offset)
    if not m:
        return -1

    cs = idaapi.get_sptr(m)
    if cs:
        return cs.id
    else:
        return -1


def IsUnion(sid):
    """
    Is a structure a union?

    @param sid: structure type ID

    @return: 1: yes, this is a union id
             0: no

    @note: Unions are a special kind of structures
    """
    s = idaapi.get_struc(sid)
    if not s:
        return 0

    return s.is_union()


def AddStrucEx(index, name, is_union):
    """
    Define a new structure type

    @param index: index of new structure type
                  If another structure has the specified index,
                  then index of that structure and all other
                  structures will be incremented, freeing the specifed
                  index. If index is == -1, then the biggest index
                  number will be used.
                  See GetFirstStrucIdx() for the explanation of
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

    return idaapi.add_struc(index, name, is_union)


def DelStruc(sid):
    """
    Delete a structure type

    @param sid: structure type ID

    @return: 0 if bad structure type ID is passed
             1 otherwise the structure type is deleted. All data
             and other structure types referencing to the
             deleted structure type will be displayed as array
             of bytes.
    """
    s = idaapi.get_struc(sid)
    if not s:
        return 0

    return idaapi.del_struc(s)


def SetStrucIdx(sid, index):
    """
    Change structure index

    @param sid: structure type ID
    @param index: new index of the structure

    @return: != 0 - ok

    @note: See GetFirstStrucIdx() for the explanation of
           structure indices and IDs.
    """
    s = idaapi.get_struc(sid)
    if not s:
        return 0

    return idaapi.set_struc_idx(s, index)


def SetStrucName(sid, name):
    """
    Change structure name

    @param sid: structure type ID
    @param name: new name of the structure

    @return: != 0 - ok
    """
    return idaapi.set_struc_name(sid, name)


def SetStrucComment(sid, comment, repeatable):
    """
    Change structure comment

    @param sid: structure type ID
    @param comment: new comment of the structure
    @param repeatable: 1: change repeatable comment
                       0: change regular comment
    @return: != 0 - ok
    """
    return idaapi.set_struc_cmt(sid, comment, repeatable)


def AddStrucMember(sid, name, offset, flag, typeid, nbytes, target=-1, tdelta=0, reftype=REF_OFF32):
    """
    Add structure member

    @param sid: structure type ID
    @param name: name of the new member
    @param offset: offset of the new member
                   -1 means to add at the end of the structure
    @param flag: type of the new member. Should be one of
                 FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
    @param typeid: if isStruc(flag) then typeid specifies the structure id for the member
                   if isOff0(flag) then typeid specifies the offset base.
                   if isASCII(flag) then typeid specifies the string type (ASCSTR_...).
                   if isStroff(flag) then typeid specifies the structure id
                   if isEnum(flag) then typeid specifies the enum id
                   if isCustom(flags) then typeid specifies the dtid and fid: dtid|(fid<<16)
                   Otherwise typeid should be -1.
    @param nbytes: number of bytes in the new member

    @param target: target address of the offset expr. You may specify it as
                   -1, ida will calculate it itself
    @param tdelta: offset target delta. usually 0
    @param reftype: see REF_... definitions

    @note: The remaining arguments are allowed only if isOff0(flag) and you want
           to specify a complex offset expression

    @return: 0 - ok, otherwise error code (one of STRUC_ERROR_*)

    """
    if isOff0(flag):
        return Eval('AddStrucMember(%d, "%s", %d, %d, %d, %d, %d, %d, %d);' % (sid, idaapi.str2user(name), offset, flag, typeid, nbytes,
                                                                               target, tdelta, reftype))
    else:
        return Eval('AddStrucMember(%d, "%s", %d, %d, %d, %d);' % (sid, idaapi.str2user(name), offset, flag, typeid, nbytes))


STRUC_ERROR_MEMBER_NAME    = -1 # already has member with this name (bad name)
STRUC_ERROR_MEMBER_OFFSET  = -2 # already has member at this offset
STRUC_ERROR_MEMBER_SIZE    = -3 # bad number of bytes or bad sizeof(type)
STRUC_ERROR_MEMBER_TINFO   = -4 # bad typeid parameter
STRUC_ERROR_MEMBER_STRUCT  = -5 # bad struct id (the 1st argument)
STRUC_ERROR_MEMBER_UNIVAR  = -6 # unions can't have variable sized members
STRUC_ERROR_MEMBER_VARLAST = -7 # variable sized member should be the last member in the structure


def DelStrucMember(sid, member_offset):
    """
    Delete structure member

    @param sid: structure type ID
    @param member_offset: offset of the member

    @return: != 0 - ok.

    @note: IDA allows 'holes' between members of a
           structure. It treats these 'holes'
           as unnamed arrays of bytes.
    """
    s = idaapi.get_struc(sid)
    if not s:
        return 0

    return idaapi.del_struc_member(s, member_offset)


def SetMemberName(sid, member_offset, name):
    """
    Change structure member name

    @param sid: structure type ID
    @param member_offset: offset of the member
    @param name: new name of the member

    @return: != 0 - ok.
    """
    s = idaapi.get_struc(sid)
    if not s:
        return 0

    return idaapi.set_member_name(s, member_offset, name)


def SetMemberType(sid, member_offset, flag, typeid, nitems, target=-1, tdelta=0, reftype=REF_OFF32):
    """
    Change structure member type

    @param sid: structure type ID
    @param member_offset: offset of the member
    @param flag: new type of the member. Should be one of
                 FF_BYTE..FF_PACKREAL (see above) combined with FF_DATA
    @param typeid: if isStruc(flag) then typeid specifies the structure id for the member
                   if isOff0(flag) then typeid specifies the offset base.
                   if isASCII(flag) then typeid specifies the string type (ASCSTR_...).
                   if isStroff(flag) then typeid specifies the structure id
                   if isEnum(flag) then typeid specifies the enum id
                   if isCustom(flags) then typeid specifies the dtid and fid: dtid|(fid<<16)
                   Otherwise typeid should be -1.
    @param nitems: number of items in the member

    @param target: target address of the offset expr. You may specify it as
                   -1, ida will calculate it itself
    @param tdelta: offset target delta. usually 0
    @param reftype: see REF_... definitions

    @note: The remaining arguments are allowed only if isOff0(flag) and you want
           to specify a complex offset expression

    @return: !=0 - ok.
    """
    if isOff0(flag):
        return Eval('SetMemberType(%d, %d, %d, %d, %d, %d, %d, %d);' % (sid, member_offset, flag, typeid, nitems,
                                                                              target, tdelta, reftype))
    else:
        return Eval('SetMemberType(%d, %d, %d, %d, %d);' % (sid, member_offset, flag, typeid, nitems))


def SetMemberComment(sid, member_offset, comment, repeatable):
    """
    Change structure member comment

    @param sid: structure type ID
    @param member_offset: offset of the member
    @param comment: new comment of the structure member
    @param repeatable: 1: change repeatable comment
                       0: change regular comment

    @return: != 0 - ok
    """
    s = idaapi.get_struc(sid)
    if not s:
        return 0

    m = idaapi.get_member(s, member_offset)
    if not m:
        return 0

    return idaapi.set_member_cmt(m, comment, repeatable)


def ExpandStruc(sid, offset, delta, recalc):
    """
    Expand or shrink a structure type
    @param id: structure type ID
    @param offset: offset in the structure
    @param delta: how many bytes to add or remove
    @param recalc: recalculate the locations where the structure
                               type is used
    @return: != 0 - ok
    """
    s = idaapi.get_struc(sid)
    if not s:
        return 0

    return idaapi.expand_struc(s, offset, delta, recalc)


def GetFchunkAttr(ea, attr):
    """
    Get a function chunk attribute

    @param ea: any address in the chunk
    @param attr: one of: FUNCATTR_START, FUNCATTR_END, FUNCATTR_OWNER, FUNCATTR_REFQTY

    @return: desired attribute or -1
    """
    func = idaapi.get_fchunk(ea)
    return _IDC_GetAttr(func, _FUNCATTRMAP, attr) if func else BADADDR


def SetFchunkAttr(ea, attr, value):
    """
    Set a function chunk attribute

    @param ea: any address in the chunk
    @param attr: only FUNCATTR_START, FUNCATTR_END, FUNCATTR_OWNER
    @param value: desired value

    @return: 0 if failed, 1 if success
    """
    if attr in [ FUNCATTR_START, FUNCATTR_END, FUNCATTR_OWNER ]:
        chunk = idaapi.get_fchunk(ea)
        if chunk:
            _IDC_SetAttr(chunk, _FUNCATTRMAP, attr, value)
            return idaapi.update_func(chunk)
    return 0


def GetFchunkReferer(ea, idx):
    """
    Get a function chunk referer

    @param ea: any address in the chunk
    @param idx: referer index (0..GetFchunkAttr(FUNCATTR_REFQTY))

    @return: referer address or BADADDR
    """
    return idaapi.get_fchunk_referer(ea, idx)


def NextFchunk(ea):
    """
    Get next function chunk

    @param ea: any address

    @return:  the starting address of the next function chunk or BADADDR

    @note: This function enumerates all chunks of all functions in the database
    """
    func = idaapi.get_next_fchunk(ea)

    if func:
        return func.startEA
    else:
        return BADADDR


def PrevFchunk(ea):
    """
    Get previous function chunk

    @param ea: any address

    @return: the starting address of the function chunk or BADADDR

    @note: This function enumerates all chunks of all functions in the database
    """
    func = idaapi.get_prev_fchunk(ea)

    if func:
        return func.startEA
    else:
        return BADADDR


def AppendFchunk(funcea, ea1, ea2):
    """
    Append a function chunk to the function

    @param funcea: any address in the function
    @param ea1: start of function tail
    @param ea2: end of function tail
    @return: 0 if failed, 1 if success

    @note: If a chunk exists at the specified addresses, it must have exactly
           the specified boundaries
    """
    func = idaapi.get_func(funcea)

    if not func:
        return 0
    else:
        return idaapi.append_func_tail(func, ea1, ea2)


def RemoveFchunk(funcea, tailea):
    """
    Remove a function chunk from the function

    @param funcea: any address in the function
    @param tailea: any address in the function chunk to remove

    @return: 0 if failed, 1 if success
    """
    func = idaapi.get_func(funcea)

    if not func:
        return 0
    else:
        return idaapi.remove_func_tail(func, tailea)


def SetFchunkOwner(tailea, funcea):
    """
    Change the function chunk owner

    @param tailea: any address in the function chunk
    @param funcea: the starting address of the new owner

    @return: 0 if failed, 1 if success

    @note: The new owner must already have the chunk appended before the call
    """
    tail = idaapi.get_func(tailea)

    if not tail:
        return 0
    else:
        return idaapi.set_tail_owner(tail, funcea)


def FirstFuncFchunk(funcea):
    """
    Get the first function chunk of the specified function

    @param funcea: any address in the function

    @return: the function entry point or BADADDR

    @note: This function returns the first (main) chunk of the specified function
    """
    func = idaapi.get_func(funcea)
    fci = idaapi.func_tail_iterator_t(func, funcea)
    if fci.main():
        return fci.chunk().startEA
    else:
        return BADADDR


def NextFuncFchunk(funcea, tailea):
    """
    Get the next function chunk of the specified function

    @param funcea: any address in the function
    @param tailea: any address in the current chunk

    @return: the starting address of the next function chunk or BADADDR

    @note: This function returns the next chunk of the specified function
    """
    func = idaapi.get_func(funcea)
    fci = idaapi.func_tail_iterator_t(func, funcea)
    if not fci.main():
        return BADADDR

    # Iterate and try to find the current chunk
    found = False
    while True:
        if fci.chunk().startEA <= tailea and \
           fci.chunk().endEA > tailea:
            found = True
            break
        if not fci.next():
            break

    # Return the next chunk, if there is one
    if found and fci.next():
        return fci.chunk().startEA
    else:
        return BADADDR


# ----------------------------------------------------------------------------
#                          E N U M S
# ----------------------------------------------------------------------------
def GetEnumQty():
    """
    Get number of enum types

    @return: number of enumerations
    """
    return idaapi.get_enum_qty()


def GetnEnum(idx):
    """
    Get ID of the specified enum by its serial number

    @param idx: number of enum (0..GetEnumQty()-1)

    @return: ID of enum or -1 if error
    """
    return idaapi.getn_enum(idx)


def GetEnumIdx(enum_id):
    """
    Get serial number of enum by its ID

    @param enum_id: ID of enum

    @return: (0..GetEnumQty()-1) or -1 if error
    """
    return idaapi.get_enum_idx(enum_id)


def GetEnum(name):
    """
    Get enum ID by the name of enum

    Arguments:
    name - name of enum

    returns:        ID of enum or -1 if no such enum exists
    """
    return idaapi.get_enum(name)


def GetEnumName(enum_id):
    """
    Get name of enum

    @param enum_id: ID of enum

    @return: name of enum or empty string
    """
    return idaapi.get_enum_name(enum_id)


def GetEnumCmt(enum_id, repeatable):
    """
    Get comment of enum

    @param enum_id: ID of enum
    @param repeatable: 0:get regular comment
                 1:get repeatable comment

    @return: comment of enum
    """
    return idaapi.get_enum_cmt(enum_id, repeatable)


def GetEnumSize(enum_id):
    """
    Get size of enum

    @param enum_id: ID of enum

    @return:  number of constants in the enum
              Returns 0 if enum_id is bad.
    """
    return idaapi.get_enum_size(enum_id)


def GetEnumWidth(enum_id):
    """
    Get width of enum elements

    @param enum_id: ID of enum

    @return: log2(size of enum elements in bytes)+1
             possible returned values are 1..7
             1-1byte,2-2bytes,3-4bytes,4-8bytes,etc
             Returns 0 if enum_id is bad or the width is unknown.
    """
    return idaapi.get_enum_width(enum_id)


def GetEnumFlag(enum_id):
    """
    Get flag of enum

    @param enum_id: ID of enum

    @return: flags of enum. These flags determine representation
        of numeric constants (binary,octal,decimal,hex)
        in the enum definition. See start of this file for
        more information about flags.
        Returns 0 if enum_id is bad.
    """
    return idaapi.get_enum_flag(enum_id)


def GetConstByName(name):
    """
    Get member of enum - a symbolic constant ID

    @param name: name of symbolic constant

    @return: ID of constant or -1
    """
    return idaapi.get_enum_member_by_name(name)


def GetConstValue(const_id):
    """
    Get value of symbolic constant

    @param const_id: id of symbolic constant

    @return: value of constant or 0
    """
    return idaapi.get_enum_member_value(const_id)


def GetConstBmask(const_id):
    """
    Get bit mask of symbolic constant

    @param const_id: id of symbolic constant

    @return: bitmask of constant or 0
             ordinary enums have bitmask = -1
    """
    return idaapi.get_enum_member_bmask(const_id)


def GetConstEnum(const_id):
    """
    Get id of enum by id of constant

    @param const_id: id of symbolic constant

    @return: id of enum the constant belongs to.
             -1 if const_id is bad.
    """
    return idaapi.get_enum_member_enum(const_id)


def GetConstEx(enum_id, value, serial, bmask):
    """
    Get id of constant

    @param enum_id: id of enum
    @param value: value of constant
    @param serial: serial number of the constant in the
              enumeration. See OpEnumEx() for details.
    @param bmask: bitmask of the constant
              ordinary enums accept only -1 as a bitmask

    @return: id of constant or -1 if error
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.get_enum_member(enum_id, value, serial, bmask)


def GetFirstBmask(enum_id):
    """
    Get first bitmask in the enum (bitfield)

    @param enum_id: id of enum (bitfield)

    @return: the smallest bitmask of constant or -1
             no bitmasks are defined yet
             All bitmasks are sorted by their values
             as unsigned longs.
    """
    return idaapi.get_first_bmask(enum_id)


def GetLastBmask(enum_id):
    """
    Get last bitmask in the enum (bitfield)

    @param enum_id: id of enum

    @return: the biggest bitmask or -1 no bitmasks are defined yet
             All bitmasks are sorted by their values as unsigned longs.
    """
    return idaapi.get_last_bmask(enum_id)


def GetNextBmask(enum_id, value):
    """
    Get next bitmask in the enum (bitfield)

    @param enum_id: id of enum
    @param value: value of the current bitmask

    @return:  value of a bitmask with value higher than the specified
              value. -1 if no such bitmasks exist.
              All bitmasks are sorted by their values
              as unsigned longs.
    """
    return idaapi.get_next_bmask(enum_id, value)


def GetPrevBmask(enum_id, value):
    """
    Get prev bitmask in the enum (bitfield)

    @param enum_id: id of enum
    @param value: value of the current bitmask

    @return: value of a bitmask with value lower than the specified
             value. -1 no such bitmasks exist.
             All bitmasks are sorted by their values as unsigned longs.
    """
    return idaapi.get_prev_bmask(enum_id, value)


def GetBmaskName(enum_id, bmask):
    """
    Get bitmask name (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant

    @return: name of bitmask or None
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.get_bmask_name(enum_id, bmask)


def GetBmaskCmt(enum_id, bmask, repeatable):
    """
    Get bitmask comment (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant
    @param repeatable: type of comment, 0-regular, 1-repeatable

    @return: comment attached to bitmask or None
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.get_bmask_cmt(enum_id, bmask, repeatable)


def SetBmaskName(enum_id, bmask, name):
    """
    Set bitmask name (only for bitfields)

    @param enum_id: id of enum
    @param bmask: bitmask of the constant
    @param name: name of bitmask

    @return: 1-ok, 0-failed
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.set_bmask_name(enum_id, bmask, name)


def SetBmaskCmt(enum_id, bmask, cmt, repeatable):
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
    return idaapi.set_bmask_cmt(enum_id, bmask, cmt, repeatable)


def GetFirstConst(enum_id, bmask):
    """
    Get first constant in the enum

    @param enum_id: id of enum
    @param bmask: bitmask of the constant (ordinary enums accept only -1 as a bitmask)

    @return: value of constant or -1 no constants are defined
             All constants are sorted by their values as unsigned longs.
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.get_first_enum_member(enum_id, bmask)


def GetLastConst(enum_id, bmask):
    """
    Get last constant in the enum

    @param enum_id: id of enum
    @param bmask: bitmask of the constant (ordinary enums accept only -1 as a bitmask)

    @return: value of constant or -1 no constants are defined
             All constants are sorted by their values
             as unsigned longs.
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.get_last_enum_member(enum_id, bmask)


def GetNextConst(enum_id, value, bmask):
    """
    Get next constant in the enum

    @param enum_id: id of enum
    @param bmask: bitmask of the constant ordinary enums accept only -1 as a bitmask
    @param value: value of the current constant

    @return: value of a constant with value higher than the specified
             value. -1 no such constants exist.
             All constants are sorted by their values as unsigned longs.
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.get_next_enum_member(enum_id, value, bmask)


def GetPrevConst(enum_id, value, bmask):
    """
    Get prev constant in the enum

    @param enum_id: id of enum
    @param bmask  : bitmask of the constant
              ordinary enums accept only -1 as a bitmask
    @param value: value of the current constant

    @return: value of a constant with value lower than the specified
        value. -1 no such constants exist.
        All constants are sorted by their values as unsigned longs.
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.get_prev_enum_member(enum_id, value, bmask)


def GetConstName(const_id):
    """
    Get name of a constant

    @param const_id: id of const

    Returns: name of constant
    """
    name = idaapi.get_enum_member_name(const_id)

    if not name:
        return ""
    else:
        return name


def GetConstCmt(const_id, repeatable):
    """
    Get comment of a constant

    @param const_id: id of const
    @param repeatable: 0:get regular comment, 1:get repeatable comment

    @return: comment string
    """
    cmt = idaapi.get_enum_member_cmt(const_id, repeatable)

    if not cmt:
        return ""
    else:
        return cmt


def AddEnum(idx, name, flag):
    """
    Add a new enum type

    @param idx: serial number of the new enum.
            If another enum with the same serial number
            exists, then all enums with serial
            numbers >= the specified idx get their
            serial numbers incremented (in other words,
            the new enum is put in the middle of the list of enums).

            If idx >= GetEnumQty() or idx == -1
            then the new enum is created at the end of
            the list of enums.

    @param name: name of the enum.
    @param flag: flags for representation of numeric constants
                 in the definition of enum.

    @return: id of new enum or BADADDR
    """
    if idx < 0:
        idx = idx & SIZE_MAX
    return idaapi.add_enum(idx, name, flag)


def DelEnum(enum_id):
    """
    Delete enum type

    @param enum_id: id of enum

    @return: None
    """
    idaapi.del_enum(enum_id)


def SetEnumIdx(enum_id, idx):
    """
    Give another serial number to a enum

    @param enum_id: id of enum
    @param idx: new serial number.
        If another enum with the same serial number
        exists, then all enums with serial
        numbers >= the specified idx get their
        serial numbers incremented (in other words,
        the new enum is put in the middle of the list of enums).

        If idx >= GetEnumQty() then the enum is
        moved to the end of the list of enums.

    @return: comment string
    """
    return idaapi.set_enum_idx(enum_id, idx)


def SetEnumName(enum_id, name):
    """
    Rename enum

    @param enum_id: id of enum
    @param name: new name of enum

    @return: 1-ok,0-failed
    """
    return idaapi.set_enum_name(enum_id, name)


def SetEnumCmt(enum_id, cmt, repeatable):
    """
    Set comment of enum

    @param enum_id: id of enum
    @param cmt: new comment for the enum
    @param repeatable: is the comment repeatable?
        - 0:set regular comment
        - 1:set repeatable comment

    @return: 1-ok,0-failed
    """
    return idaapi.set_enum_cmt(enum_id, cmt, repeatable)


def SetEnumFlag(enum_id, flag):
    """
    Set flag of enum

    @param enum_id: id of enum
    @param flag: flags for representation of numeric constants
        in the definition of enum.

    @return: 1-ok,0-failed
    """
    return idaapi.set_enum_flag(enum_id, flag)


def SetEnumBf(enum_id, flag):
    """
    Set bitfield property of enum

    @param enum_id: id of enum
    @param flag: flags
        - 1: convert to bitfield
        - 0: convert to ordinary enum

    @return: 1-ok,0-failed
    """
    return idaapi.set_enum_bf(enum_id, flag)


def SetEnumWidth(enum_id, width):
    """
    Set width of enum elements

    @param enum_id: id of enum
    @param width: element width in bytes
                  allowed values: 0-unknown
                  or 1..7: (log2 of the element size)+1

    @return: 1-ok, 0-failed
    """
    return idaapi.set_enum_width(enum_id, width)


def IsBitfield(enum_id):
    """
    Is enum a bitfield?

    @param enum_id: id of enum

    @return: 1-yes, 0-no, ordinary enum
    """
    return idaapi.is_bf(enum_id)


def AddConstEx(enum_id, name, value, bmask):
    """
    Add a member of enum - a symbolic constant

    @param enum_id: id of enum
    @param name: name of symbolic constant. Must be unique in the program.
    @param value: value of symbolic constant.
    @param bmask: bitmask of the constant
        ordinary enums accept only -1 as a bitmask
        all bits set in value should be set in bmask too

    @return: 0-ok, otherwise error code (one of ENUM_MEMBER_ERROR_*)
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.add_enum_member(enum_id, name, value, bmask)


ENUM_MEMBER_ERROR_NAME  = idaapi.ENUM_MEMBER_ERROR_NAME  # already have member with this name (bad name)
ENUM_MEMBER_ERROR_VALUE = idaapi.ENUM_MEMBER_ERROR_VALUE # already have member with this value
ENUM_MEMBER_ERROR_ENUM  = idaapi.ENUM_MEMBER_ERROR_ENUM  # bad enum id
ENUM_MEMBER_ERROR_MASK  = idaapi.ENUM_MEMBER_ERROR_MASK  # bad bmask
ENUM_MEMBER_ERROR_ILLV  = idaapi.ENUM_MEMBER_ERROR_ILLV  # bad bmask and value combination (~bmask & value != 0)


def DelConstEx(enum_id, value, serial, bmask):
    """
    Delete a member of enum - a symbolic constant

    @param enum_id: id of enum
    @param value: value of symbolic constant.
    @param serial: serial number of the constant in the
        enumeration. See OpEnumEx() for for details.
    @param bmask: bitmask of the constant ordinary enums accept
        only -1 as a bitmask

    @return: 1-ok, 0-failed
    """
    if bmask < 0:
        bmask &= BADADDR
    return idaapi.del_enum_member(enum_id, value, serial, bmask)


def SetConstName(const_id, name):
    """
    Rename a member of enum - a symbolic constant

    @param const_id: id of const
    @param name: new name of constant

    @return: 1-ok, 0-failed
    """
    return idaapi.set_enum_member_name(const_id, name)


def SetConstCmt(const_id, cmt, repeatable):
    """
    Set a comment of a symbolic constant

    @param const_id: id of const
    @param cmt: new comment for the constant
    @param repeatable: is the comment repeatable?
        0: set regular comment
        1: set repeatable comment

    @return: 1-ok, 0-failed
    """
    return idaapi.set_enum_member_cmt(const_id, cmt, repeatable)

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
    if v == idaapi.BADNODE:
        return -1
    else:
        return v



AR_LONG = idaapi.atag
"""Array of longs"""

AR_STR = idaapi.stag
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
    def alt1st(self, *args): return -1
    def sup1st(self, *args): return -1
    def altlast(self, *args): return -1
    def suplast(self, *args): return -1
    def altnxt(self, *args): return -1
    def supnxt(self, *args): return -1
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
    def hash1st(self, *args): return 0
    def hashnxt(self, *args): return 0
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
        node = idaapi.netnode(array_id)
        nodename = node.name()
        if nodename is None or not nodename.startswith(_IDC_ARRAY_PREFIX):
            return __dummy_netnode.instance
        else:
            return node
    except NotImplementedError:
        return __dummy_netnode.instance


def CreateArray(name):
    """
    Create array.

    @param name: The array name.

    @return: -1 in case of failure, a valid array_id otherwise.
    """
    node = idaapi.netnode()
    res  = node.create(_IDC_ARRAY_PREFIX + name)
    if res == False:
        return -1
    else:
        return node.index()


def GetArrayId(name):
    """
    Get array array_id, by name.

    @param name: The array name.

    @return: -1 in case of failure (i.e., no array with that
             name exists), a valid array_id otherwise.
    """
    return __l2m1(idaapi.netnode(_IDC_ARRAY_PREFIX + name, 0, False).index())


def RenameArray(array_id, newname):
    """
    Rename array, by its ID.

    @param id: The ID of the array to rename.
    @param newname: The new name of the array.

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(array_id).rename(_IDC_ARRAY_PREFIX + newname) == 1


def DeleteArray(array_id):
    """
    Delete array, by its ID.

    @param array_id: The ID of the array to delete.
    """
    __GetArrayById(array_id).kill()


def SetArrayLong(array_id, idx, value):
    """
    Sets the long value of an array element.

    @param array_id: The array ID.
    @param idx: Index of an element.
    @param value: 32bit or 64bit value to store in the array

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(array_id).altset(idx, value)


def SetArrayString(array_id, idx, value):
    """
    Sets the string value of an array element.

    @param array_id: The array ID.
    @param idx: Index of an element.
    @param value: String value to store in the array

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(array_id).supset(idx, value)


def GetArrayElement(tag, array_id, idx):
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


def DelArrayElement(tag, array_id, idx):
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


def GetFirstIndex(tag, array_id):
    """
    Get index of the first existing array element.

    @param tag: Tag of array, specifies one of two array types: AR_LONG, AR_STR
    @param array_id: The array ID.

    @return: -1 if the array is empty, otherwise index of first array
             element of given type.
    """
    node = __GetArrayById(array_id)
    if tag == AR_LONG:
        return __l2m1(node.alt1st(tag))
    elif tag == AR_STR:
        return __l2m1(node.sup1st(tag))
    else:
        return -1


def GetLastIndex(tag, array_id):
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


def GetNextIndex(tag, array_id, idx):
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
            return __l2m1(node.altnxt(idx, tag))
        elif tag == AR_STR:
            return __l2m1(node.supnxt(idx, tag))
        else:
            return -1
    except OverflowError:
        # typically: An index of -1 was passed.
        return -1


def GetPrevIndex(tag, array_id, idx):
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

def SetHashLong(hash_id, key, value):
    """
    Sets the long value of a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element.
    @param value: 32bit or 64bit value to store in the hash

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(hash_id).hashset_idx(key, value)


def GetHashLong(hash_id, key):
    """
    Gets the long value of a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element.

    @return: the 32bit or 64bit value of the element, or 0 if no such
             element.
    """
    return __GetArrayById(hash_id).hashval_long(key);


def SetHashString(hash_id, key, value):
    """
    Sets the string value of a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element.
    @param value: string value to store in the hash

    @return: 1 in case of success, 0 otherwise
    """
    return __GetArrayById(hash_id).hashset_buf(key, value)


def GetHashString(hash_id, key):
    """
    Gets the string value of a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element.

    @return: the string value of the element, or None if no such
             element.
    """
    return __GetArrayById(hash_id).hashstr_buf(key);


def DelHashElement(hash_id, key):
    """
    Delete a hash element.

    @param hash_id: The hash ID.
    @param key: Key of an element

    @return: 1 upon success, 0 otherwise.
    """
    return __GetArrayById(hash_id).hashdel(key)


def GetFirstHashKey(hash_id):
    """
    Get the first key in the hash.

    @param hash_id: The hash ID.

    @return: the key, 0 otherwise.
    """
    r = __GetArrayById(hash_id).hash1st()
    return 0 if r is None else r


def GetLastHashKey(hash_id):
    """
    Get the last key in the hash.

    @param hash_id: The hash ID.

    @return: the key, 0 otherwise.
    """
    r = __GetArrayById(hash_id).hashlast()
    return 0 if r is None else r


def GetNextHashKey(hash_id, key):
    """
    Get the next key in the hash.

    @param hash_id: The hash ID.
    @param key: The current key.

    @return: the next key, 0 otherwise
    """
    r = __GetArrayById(hash_id).hashnxt(key)
    return 0 if r is None else r


def GetPrevHashKey(hash_id, key):
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
def AddSourceFile(ea1, ea2, filename):
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
    return idaapi.add_sourcefile(ea1, ea2, filename)


def GetSourceFile(ea):
    """
    Get name of source file occupying the given address

    @param ea: linear address

    @return: NULL - source file information is not found
             otherwise returns pointer to file name
    """
    return idaapi.get_sourcefile(ea)


def DelSourceFile(ea):
    """
    Delete information about the source file

    @param ea: linear address belonging to the source file

    @return: NULL - source file information is not found
             otherwise returns pointer to file name
    """
    return idaapi.del_sourcefile(ea)


def SetLineNumber(ea, lnnum):
    """
    Set source line number

    @param ea: linear address
    @param lnnum: number of line in the source file

    @return: None
    """
    idaapi.set_source_linnum(ea, lnnum)


def GetLineNumber(ea):
    """
    Get source line number

    @param ea: linear address

    @return: number of line in the source file or -1
    """
    return idaapi.get_source_linnum(ea)


def DelLineNumber(ea):
    """
    Delete information about source line number

    @param ea: linear address

    @return: None
    """
    idaapi.del_source_linnum(ea)


#----------------------------------------------------------------------------
#                T Y P E  L I B R A R I E S
#----------------------------------------------------------------------------

def LoadTil(name):
    """
    Load a type library

    @param name: name of type library.
    @return: 1-ok, 0-failed.
    """
    til = idaapi.add_til2(name, idaapi.ADDTIL_DEFAULT)

    if til:
        return 1
    else:
        return 0


def Til2Idb(idx, type_name):
    """
    Copy information from type library to database
    Copy structure, union, or enum definition from the type library
    to the IDA database.

    @param idx: the position of the new type in the list of
                types (structures or enums) -1 means at the end of the list
    @param type_name: name of type to copy

    @return: BADNODE-failed, otherwise the type id (structure id or enum id)
    """
    return idaapi.import_type(idaapi.cvar.idati, idx, type_name)


def GetType(ea):
    """
    Get type of function/variable

    @param ea: the address of the object

    @return: type string or None if failed
    """
    return idaapi.idc_get_type(ea)

def SizeOf(typestr):
    """
    Returns the size of the type. It is equivalent to IDC's sizeof().
    Use name, tp, fld = idc.ParseType() ; SizeOf(tp) to retrieve the size
    @return: -1 if typestring is not valid otherwise the size of the type
    """
    return idaapi.calc_type_size(idaapi.cvar.idati, typestr)

def GetTinfo(ea):
    """
    Get type information of function/variable as 'typeinfo' object

    @param ea: the address of the object
    @return: None on failure, or (type, fields) tuple.
    """
    return idaapi.idc_get_type_raw(ea)

def GetLocalTinfo(ordinal):
    """
    Get local type information as 'typeinfo' object

    @param ordinal:  slot number (1...NumberOfLocalTypes)
    @return: None on failure, or (type, fields, name) tuple.
    """
    return idaapi.idc_get_local_type_raw(ordinal)

def GuessType(ea):
    """
    Guess type of function/variable

    @param ea: the address of the object, can be the structure member id too

    @return: type string or None if failed
    """
    return idaapi.idc_guess_type(ea)

TINFO_GUESSED   = 0x0000 # this is a guessed type
TINFO_DEFINITE  = 0x0001 # this is a definite type
TINFO_DELAYFUNC = 0x0002 # if type is a function and no function exists at ea,
                         # schedule its creation and argument renaming to
                         # auto-analysis otherwise try to create it immediately

def ApplyType(ea, py_type, flags = TINFO_DEFINITE):
    """
    Apply the specified type to the address

    @param ti: Type info. 'idaapi.cvar.idati' can be passed.
    @param py_type: typeinfo tuple (type, fields) as GetTinfo() returns
                 or tuple (name, type, fields) as ParseType() returns
                 or None
                if specified as None, then the
                item associated with 'ea' will be deleted.
    @param ea: the address of the object
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
    return idaapi.apply_type(idaapi.cvar.idati, pt[0], pt[1], ea, flags)

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
        pt = ParseType(newtype, 1) # silent
        if pt is None:
          # parsing failed
          return None
    else:
        pt = None
    return ApplyType(ea, pt, TINFO_DEFINITE)

def ParseType(inputtype, flags):
    """
    Parse type declaration

    @param inputtype: file name or C declarations (depending on the flags)
    @param flags: combination of PT_... constants or 0

    @return: None on failure or (name, type, fields) tuple
    """
    if len(inputtype) != 0 and inputtype[-1] != ';':
        inputtype = inputtype + ';'
    return idaapi.idc_parse_decl(idaapi.cvar.idati, inputtype, flags)

def ParseTypes(inputtype, flags = 0):
    """
    Parse type declarations

    @param inputtype: file name or C declarations (depending on the flags)
    @param flags: combination of PT_... constants or 0

    @return: number of parsing errors (0 no errors)
    """
    return idaapi.idc_parse_types(inputtype, flags)


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


def GetMaxLocalType():
    """
    Get number of local types + 1

    @return: value >= 1. 1 means that there are no local types.
    """
    return idaapi.get_ordinal_qty(idaapi.cvar.idati)


def SetLocalType(ordinal, input, flags):
    """
    Parse one type declaration and store it in the specified slot

    @param ordinal:  slot number (1...NumberOfLocalTypes)
                     -1 means allocate new slot or reuse the slot
                     of the existing named type
    @param input:  C declaration. Empty input empties the slot
    @param flags:  combination of PT_... constants or 0

    @return: slot number or 0 if error
    """
    return idaapi.idc_set_local_type(ordinal, input, flags)


def GetLocalType(ordinal, flags):
    """
    Retrieve a local type declaration
    @param flags: any of PRTYPE_* constants
    @return: local type as a C declaration or ""
    """
    (type, fields) = GetLocalTinfo(ordinal)
    if type:
      name = GetLocalTypeName(ordinal)
      return idaapi.idc_print_type(type, fields, name, flags)
    return ""

PRTYPE_1LINE  = 0x0000 # print to one line
PRTYPE_MULTI  = 0x0001 # print to many lines
PRTYPE_TYPE   = 0x0002 # print type declaration (not variable declaration)
PRTYPE_PRAGMA = 0x0004 # print pragmas for alignment


def GetLocalTypeName(ordinal):
    """
    Retrieve a local type name

    @param ordinal:  slot number (1...NumberOfLocalTypes)

    returns: local type name or None
    """
    return idaapi.idc_get_local_type_name(ordinal)


# ----------------------------------------------------------------------------
#                           H I D D E N  A R E A S
# ----------------------------------------------------------------------------
def HideArea(start, end, description, header, footer, color):
    """
    Hide an area

    Hidden areas - address ranges which can be replaced by their descriptions

    @param start:       area start
    @param end:         area end
    @param description: description to display if the area is collapsed
    @param header:      header lines to display if the area is expanded
    @param footer:      footer lines to display if the area is expanded
    @param color:       RGB color code (-1 means default color)

    @returns:    !=0 - ok
    """
    return idaapi.add_hidden_area(start, end, description, header, footer, color)


def SetHiddenArea(ea, visible):
    """
    Set hidden area state

    @param ea:      any address belonging to the hidden area
    @param visible: new state of the area

    @return: != 0 - ok
    """
    ha = idaapi.get_hidden_area(ea)

    if not ha:
        return 0
    else:
        ha.visible = visible
        return idaapi.update_hidden_area(ha)


def DelHiddenArea(ea):
    """
    Delete a hidden area

    @param ea: any address belonging to the hidden area
    @returns:  != 0 - ok
    """
    return idaapi.del_hidden_area(ea)


#--------------------------------------------------------------------------
#                   D E B U G G E R  I N T E R F A C E
#--------------------------------------------------------------------------
def LoadDebugger(dbgname, use_remote):
    """
    Load the debugger

    @param dbgname: debugger module name Examples: win32, linux, mac.
    @param use_remote: 0/1: use remote debugger or not

    @note: This function is needed only when running idc scripts from the command line.
           In other cases IDA loads the debugger module automatically.
    """
    return idaapi.load_debugger(dbgname, use_remote)


def StartDebugger(path, args, sdir):
    """
    Launch the debugger

    @param path: path to the executable file.
    @param args: command line arguments
    @param sdir: initial directory for the process

    @return: -1-failed, 0-cancelled by the user, 1-ok

    @note: For all args: if empty, the default value from the database will be used
           See the important note to the StepInto() function
    """
    return idaapi.start_process(path, args, sdir)


def StopDebugger():
    """
    Stop the debugger
    Kills the currently debugger process and returns to the disassembly mode

    @return: success
    """
    return idaapi.exit_process()


def PauseProcess():
    """
    Suspend the running process
    Tries to suspend the process. If successful, the PROCESS_SUSPEND
    debug event will arrive (see GetDebuggerEvent)

    @return: success

    @note: To resume a suspended process use the GetDebuggerEvent function.
           See the important note to the StepInto() function
    """
    return idaapi.suspend_process()


def GetProcessQty():
    """
    Take a snapshot of running processes and return their number.
    """
    return idaapi.get_process_qty()


def GetProcessPid(idx):
    """
    Get the process ID of a running process

    @param idx: number of process, is in range 0..GetProcessQty()-1

    @return: 0 if failure
    """
    pinfo = idaapi.process_info_t()
    pid = idaapi.get_process_info(idx, pinfo)
    if pid != idaapi.NO_PROCESS:
        return pinfo.pid
    else:
        return 0


def GetProcessName(idx):
    """
    Get the name of a running process

    @param idx: number of process, is in range 0..GetProcessQty()-1

    @return: None if failure
    """
    pinfo = idaapi.process_info_t()
    pid = idaapi.get_process_info(idx, pinfo)
    return None if pid == idaapi.NO_PROCESS else pinfo.name


def AttachProcess(pid, event_id):
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
    @note: See the important note to the StepInto() function
    """
    return idaapi.attach_process(pid, event_id)


def DetachProcess():
    """
    Detach the debugger from the debugged process.

    @return: success
    """
    return idaapi.detach_process()


def GetThreadQty():
    """
    Get number of threads.

    @return: number of threads
    """
    return idaapi.get_thread_qty()


def GetThreadId(idx):
    """
    Get the ID of a thread

    @param idx: number of thread, is in range 0..GetThreadQty()-1

    @return: -1 if failure
    """
    return idaapi.getn_thread(idx)


def GetCurrentThreadId():
    """
    Get current thread ID

    @return: -1 if failure
    """
    return idaapi.get_current_thread()


def SelectThread(tid):
    """
    Select the given thread as the current debugged thread.

    @param tid: ID of the thread to select

    @return: success

    @note: The process must be suspended to select a new thread.
    """
    return idaapi.select_thread(tid)


def SuspendThread(tid):
    """
    Suspend thread

    @param tid: thread id

    @return: -1:network error, 0-failed, 1-ok

    @note: Suspending a thread may deadlock the whole application if the suspended
           was owning some synchronization objects.
    """
    return idaapi.suspend_thread(tid)


def ResumeThread(tid):
    """
    Resume thread

    @param tid: thread id

    @return: -1:network error, 0-failed, 1-ok
    """
    return idaapi.resume_thread(tid)


def _get_modules():
    """
    INTERNAL: Enumerate process modules
    """
    module = idaapi.module_info_t()
    result = idaapi.get_first_module(module)
    while result:
        yield module
        result = idaapi.get_next_module(module)


def GetFirstModule():
    """
    Enumerate process modules

    @return: first module's base address or None on failure
    """
    for module in _get_modules():
        return module.base
    else:
        return None


def GetNextModule(base):
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


def GetModuleName(base):
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


def GetModuleSize(base):
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


def StepInto():
    """
    Execute one instruction in the current thread.
    Other threads are kept suspended.

    @return: success

    @note: You must call GetDebuggerEvent() after this call
           in order to find out what happened. Normally you will
           get the STEP event but other events are possible (for example,
           an exception might occur or the process might exit).
           This remark applies to all execution control functions.
           The event codes depend on the issued command.
    """
    return idaapi.step_into()


def StepOver():
    """
    Execute one instruction in the current thread,
    but without entering into functions
    Others threads keep suspended.
    See the important note to the StepInto() function

    @return: success
    """
    return idaapi.step_over()


def RunTo(ea):
    """
    Execute the process until the given address is reached.
    If no process is active, a new process is started.
    See the important note to the StepInto() function

    @return: success
    """
    return idaapi.run_to(ea)


def StepUntilRet():
    """
    Execute instructions in the current thread until
    a function return instruction is reached.
    Other threads are kept suspended.
    See the important note to the StepInto() function

    @return: success
    """
    return idaapi.step_until_ret()


def GetDebuggerEvent(wfne, timeout):
    """
    Wait for the next event
    This function (optionally) resumes the process
    execution and wait for a debugger event until timeout

    @param wfne: combination of WFNE_... constants
    @param timeout: number of seconds to wait, -1-infinity

    @return: debugger event codes, see below
    """
    return idaapi.wait_for_next_event(wfne, timeout)


def ResumeProcess():
    return GetDebuggerEvent(WFNE_CONT|WFNE_NOWAIT, 0)

def SendDbgCommand(cmd):
    """Sends a command to the debugger module and returns the output string.
    An exception will be raised if the debugger is not running or the current debugger does not export
    the 'SendDbgCommand' IDC command.
    """
    s = Eval('SendDbgCommand("%s");' % idaapi.str2user(cmd))
    if s.startswith("IDC_FAILURE"):
        raise Exception, "Debugger command is available only when the debugger is active!"
    return s

# wfne flag is combination of the following:
WFNE_ANY    = 0x0001 # return the first event (even if it doesn't suspend the process)
                     # if the process is still running, the database
                     # does not reflect the memory state. you might want
                     # to call RefreshDebuggerMemory() in this case
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


def RefreshDebuggerMemory():
    """
    Refresh debugger memory
    Upon this call IDA will forget all cached information
    about the debugged process. This includes the segmentation
    information and memory contents (register cache is managed
    automatically). Also, this function refreshes exported name
    from loaded DLLs.
    You must call this function before using the segmentation
    information, memory contents, or names of a non-suspended process.
    This is an expensive call.
    """
    return idaapi.refresh_debugger_memory()


def TakeMemorySnapshot(only_loader_segs):
    """
    Take memory snapshot of the debugged process

    @param only_loader_segs: 0-copy all segments to idb
                             1-copy only SFL_LOADER segments
    """
    return idaapi.take_memory_snapshot(only_loader_segs)


def GetProcessState():
    """
    Get debugged process state

    @return: one of the DBG_... constants (see below)
    """
    return idaapi.get_process_state()

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

def GetEventId():
    """
    Get ID of debug event

    @return: event ID
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.eid


def GetEventPid():
    """
    Get process ID for debug event

    @return: process ID
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.pid


def GetEventTid():
    """
    Get type ID for debug event

    @return: type ID
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.tid


def GetEventEa():
    """
    Get ea for debug event

    @return: ea
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.ea


def IsEventHandled():
    """
    Is the debug event handled?

    @return: boolean
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.handled


# For PROCESS_START, PROCESS_ATTACH, LIBRARY_LOAD events:

def GetEventModuleName():
    """
    Get module name for debug event

    @return: module name
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return idaapi.get_event_module_name(ev)


def GetEventModuleBase():
    """
    Get module base for debug event

    @return: module base
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return idaapi.get_event_module_base(ev)


def GetEventModuleSize():
    """
    Get module size for debug event

    @return: module size
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return idaapi.get_event_module_size(ev)


def GetEventExitCode():
    """
    Get exit code for debug event

    @return: exit code for PROCESS_EXIT, THREAD_EXIT events
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return ev.exit_code


def GetEventInfo():
    """
    Get debug event info

    @return: event info: for LIBRARY_UNLOAD (unloaded library name)
                         for INFORMATION (message to display)
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return idaapi.get_event_info(ev)


def GetEventBptHardwareEa():
    """
    Get hardware address for BREAKPOINT event

    @return: hardware address
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return idaapi.get_event_bpt_hea(ev)


def GetEventExceptionCode():
    """
    Get exception code for EXCEPTION event

    @return: exception code
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return idaapi.get_event_exc_code(ev)


def GetEventExceptionEa():
    """
    Get address for EXCEPTION event

    @return: adress of exception
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return idaapi.get_event_exc_ea(ev)


def CanExceptionContinue():
    """
    Can it continue after EXCEPTION event?

    @return: boolean
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return idaapi.can_exc_continue(ev)


def GetEventExceptionInfo():
    """
    Get info for EXCEPTION event

    @return: info string
    """
    ev = idaapi.get_debug_event()
    assert ev, "Could not retrieve debug event"
    return idaapi.get_event_exc_info(ev)


def SetDebuggerOptions(opt):
    """
    Get/set debugger options

    @param opt: combination of DOPT_... constants

    @return: old options
    """
    return idaapi.set_debugger_options(opt)


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


def GetDebuggerEventCondition():
    """
    Return the debugger event condition
    """
    return idaapi.get_debugger_event_cond()


def SetDebuggerEventCondition(cond):
    """
    Set the debugger event condition
    """
    return idaapi.set_debugger_event_cond(cond)


def SetRemoteDebugger(hostname, password, portnum):
    """
    Set remote debugging options

    @param hostname: remote host name or address if empty, revert to local debugger
    @param password: password for the debugger server
    @param portnum: port number to connect (-1: don't change)

    @return: nothing
    """
    return idaapi.set_remote_debugger(hostname, password, portnum)


def GetExceptionQty():
    """
    Get number of defined exception codes
    """
    return idaapi.get_exception_qty()


def GetExceptionCode(idx):
    """
    Get exception code

    @param idx: number of exception in the vector (0..GetExceptionQty()-1)

    @return: exception code (0 - error)
    """
    return idaapi.get_exception_code(idx)


def GetExceptionName(code):
    """
    Get exception information

    @param code: exception code

    @return: "" on error
    """
    return idaapi.get_exception_name(code)


def GetExceptionFlags(code):
    """
    Get exception information

    @param code: exception code

    @return: -1 on error
    """
    return idaapi.get_exception_flags(code)

def DefineException(code, name, desc, flags):
    """
    Add exception handling information

    @param code: exception code
    @param name: exception name
    @param desc: exception description
    @param flags: exception flags (combination of EXC_...)

    @return: failure description or ""
    """
    return idaapi.define_exception(code, name, desc, flags)

EXC_BREAK  = 0x0001 # break on the exception
EXC_HANDLE = 0x0002 # should be handled by the debugger?


def SetExceptionFlags(code, flags):
    """
    Set exception flags

    @param code: exception code
    @param flags: exception flags (combination of EXC_...)
    """
    return idaapi.set_exception_flags(code, flags)


def ForgetException(code):
    """
    Delete exception handling information

    @param code: exception code
    """
    return idaapi.forget_exception(code)


def GetRegValue(name):
    """
    Get register value

    @param name: the register name

    @note: The debugger should be running. otherwise the function fails
           the register name should be valid.
           It is not necessary to use this function to get register values
           because a register name in the script will do too.

    @return: register value (integer or floating point)
    """
    rv = idaapi.regval_t()
    res = idaapi.get_reg_val(name, rv)
    assert res, "get_reg_val() failed, bogus register name ('%s') perhaps?" % name
    return rv.ival


def SetRegValue(value, name):
    """
    Set register value

    @param name: the register name
    @param value: new register value

    @note: The debugger should be running
           It is not necessary to use this function to set register values.
           A register name in the left side of an assignment will do too.
    """
    rv = idaapi.regval_t()
    if type(value) == types.StringType:
        value = int(value, 16)
    elif type(value) != types.IntType and type(value) != types.LongType:
        print "SetRegValue: value must be integer!"
        return BADADDR

    if value < 0:
        #ival_set cannot handle negative numbers
        value &= 0xFFFFFFFF

    rv.ival = value
    return idaapi.set_reg_val(name, rv)


def GetBptQty():
    """
    Get number of breakpoints.

    @return: number of breakpoints
    """
    return idaapi.get_bpt_qty()


def GetBptEA(n):
    """
    Get breakpoint address

    @param n: number of breakpoint, is in range 0..GetBptQty()-1

    @return: addresss of the breakpoint or BADADDR
    """
    bpt = idaapi.bpt_t()

    if idaapi.getn_bpt(n, bpt):
        return bpt.ea
    else:
        return BADADDR


def GetBptAttr(ea, bptattr):
    """
    Get the characteristics of a breakpoint

    @param ea: any address in the breakpoint range
    @param bptattr: the desired attribute code, one of BPTATTR_... constants

    @return: the desired attribute value or -1
    """
    bpt = idaapi.bpt_t()

    if not idaapi.get_bpt(ea, bpt):
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


def SetBptAttr(address, bptattr, value):
    """
        modifiable characteristics of a breakpoint

    @param address: any address in the breakpoint range
    @param bptattr: the attribute code, one of BPTATTR_* constants
                    BPTATTR_CND is not allowed, see SetBptCnd()
    @param value: the attibute value

    @return: success
    """
    bpt = idaapi.bpt_t()

    if not idaapi.get_bpt(address, bpt):
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

        idaapi.update_bpt(bpt)
        return True

def SetBptCndEx(ea, cnd, is_lowcnd):
    """
    Set breakpoint condition

    @param ea: any address in the breakpoint range
    @param cnd: breakpoint condition
    @param is_lowcnd: 0 - regular condition, 1 - low level condition

    @return: success
    """
    bpt = idaapi.bpt_t()

    if not idaapi.get_bpt(ea, bpt):
        return False

    bpt.condition = cnd
    if is_lowcnd:
        bpt.flags |= BPT_LOWCND
    else:
        bpt.flags &= ~BPT_LOWCND

    return idaapi.update_bpt(bpt)


def SetBptCnd(ea, cnd):
    """
    Set breakpoint condition

    @param ea: any address in the breakpoint range
    @param cnd: breakpoint condition

    @return: success
    """
    return SetBptCndEx(ea, cnd, 0)


def AddBptEx(ea, size, bpttype):
    """
    Add a new breakpoint

    @param ea: any address in the process memory space:
    @param size: size of the breakpoint (irrelevant for software breakpoints):
    @param bpttype: type of the breakpoint (one of BPT_... constants)

    @return: success

    @note: Only one breakpoint can exist at a given address.
    """
    return idaapi.add_bpt(ea, size, bpttype)


def AddBpt(ea):
    return AddBptEx(ea, 0, BPT_DEFAULT)


def DelBpt(ea):
    """
    Delete breakpoint

    @param ea: any address in the process memory space:

    @return: success
    """
    return idaapi.del_bpt(ea)


def EnableBpt(ea, enable):
    """
    Enable/disable breakpoint

    @param ea: any address in the process memory space

    @return: success

    @note: Disabled breakpoints are not written to the process memory
    """
    return idaapi.enable_bpt(ea, enable)


def CheckBpt(ea):
    """
    Check a breakpoint

    @param ea: address in the process memory space

    @return: one of BPTCK_... constants
    """
    return idaapi.check_bpt(ea)

BPTCK_NONE = -1  # breakpoint does not exist
BPTCK_NO   =  0  # breakpoint is disabled
BPTCK_YES  =  1  # breakpoint is enabled
BPTCK_ACT  =  2  # breakpoint is active (written to the process)


def EnableTracing(trace_level, enable):
    """
    Enable step tracing

    @param trace_level:  what kind of trace to modify
    @param enable: 0: turn off, 1: turn on

    @return: success
    """
    assert trace_level in [ TRACE_STEP, TRACE_INSN, TRACE_FUNC ], \
        "trace_level must be one of TRACE_* constants"

    if trace_level == TRACE_STEP:
        return idaapi.enable_step_trace(enable)

    if trace_level == TRACE_INSN:
        return idaapi.enable_insn_trace(enable)

    if trace_level == TRACE_FUNC:
        return idaapi.enable_func_trace(enable)

    return False

TRACE_STEP = 0x0  # lowest level trace. trace buffers are not maintained
TRACE_INSN = 0x1  # instruction level trace
TRACE_FUNC = 0x2  # function level trace (calls & rets)


def GetStepTraceOptions():
    """
    Get step current tracing options

    @return: a combination of ST_... constants
    """
    return idaapi.get_step_trace_options()


def SetStepTraceOptions(options):
    """
    Set step current tracing options.
    @param options: combination of ST_... constants
    """
    return idaapi.set_step_trace_options(options)


ST_OVER_DEBUG_SEG = 0x01 # step tracing will be disabled when IP is in a debugger segment
ST_OVER_LIB_FUNC  = 0x02 # step tracing will be disabled when IP is in a library function
ST_ALREADY_LOGGED = 0x04 # step tracing will be disabled when IP is already logged
ST_SKIP_LOOPS     = 0x08 # step tracing will try to skip loops already recorded

def LoadTraceFile(filename):
    """
    Load a previously recorded binary trace file
    @param filename: trace file
    """
    return idaapi.load_trace_file(filename)

def SaveTraceFile(filename, description):
    """
    Save current trace to a binary trace file
    @param filename: trace file
    @param description: trace description
    """
    return idaapi.save_trace_file(filename, description)

def CheckTraceFile(filename):
    """
    Check the given binary trace file
    @param filename: trace file
    """
    return idaapi.is_valid_trace_file(filename)

def DiffTraceFile(filename):
    """
    Diff current trace buffer against given trace
    @param filename: trace file
    """
    return idaapi.diff_trace_file(filename)

def ClearTraceFile(filename):
    """
    Clear the current trace buffer
    """
    return idaapi.clear_trace()

def GetTraceDesc(filename):
    """
    Get the trace description of the given binary trace file
    @param filename: trace file
    """
    return idaapi.get_trace_file_desc(filename)

def SetTraceDesc(filename, description):
    """
    Update the trace description of the given binary trace file
    @param filename: trace file
    @description: trace description
    """
    return idaapi.set_trace_file_desc(filename, description)

def GetMaxTev():
    """
    Return the total number of recorded events
    """
    return idaapi.get_tev_qty()

def GetTevEa(tev):
    """
    Return the address of the specified event
    @param tev: event number
    """
    return idaapi.get_tev_ea(tev)

TEV_NONE  = 0 # no event
TEV_INSN  = 1 # an instruction trace
TEV_CALL  = 2 # a function call trace
TEV_RET   = 3 # a function return trace
TEV_BPT   = 4 # write, read/write, execution trace
TEV_MEM   = 5 # memory layout changed
TEV_EVENT = 6 # debug event

def GetTevType(tev):
    """
    Return the type of the specified event (TEV_... constants)
    @param tev: event number
    """
    return idaapi.get_tev_type(tev)

def GetTevTid(tev):
    """
    Return the thread id of the specified event
    @param tev: event number
    """
    return idaapi.get_tev_tid(tev)

def GetTevRegVal(tev, reg):
    """
    Return the register value for the specified event
    @param tev: event number
    @param reg: register name (like EAX, RBX, ...)
    """
    return idaapi.get_tev_reg_val(tev, reg)

def GetTevRegMemQty(tev):
    """
    Return the number of memory addresses recorded for the specified event
    @param tev: event number
    """
    return idaapi.get_tev_reg_mem_qty(tev)

def GetTevRegMem(tev, idx):
    """
    Return the memory pointed by 'index' for the specified event
    @param tev: event number
    @param idx: memory address index
    """
    return idaapi.get_tev_reg_mem(tev, idx)

def GetTevRegMemEa(tev, idx):
    """
    Return the address pointed by 'index' for the specified event
    @param tev: event number
    @param idx: memory address index
    """
    return idaapi.get_tev_reg_mem_ea(tev, idx)

def GetTevCallee(tev):
    """
    Return the address of the callee for the specified event
    @param tev: event number
    """
    return idaapi.get_call_tev_callee(tev)

def GetTevReturn(tev):
    """
    Return the return address for the specified event
    @param tev: event number
    """
    return idaapi.get_ret_tev_return(tev)

def GetBptTevEa(tev):
    """
    Return the address of the specified TEV_BPT event
    @param tev: event number
    """
    return idaapi.get_bpt_tev_ea(tev)


#--------------------------------------------------------------------------
#                             C O L O R S
#--------------------------------------------------------------------------

def GetColor(ea, what):
    """
    Get item color

    @param ea: address of the item
    @param what: type of the item (one of  CIC_* constants)

    @return: color code in RGB (hex 0xBBGGRR)
    """
    if what not in [ CIC_ITEM, CIC_FUNC, CIC_SEGM ]:
        raise ValueError, "'what' must be one of CIC_ITEM, CIC_FUNC and CIC_SEGM"

    if what == CIC_ITEM:
        return idaapi.get_item_color(ea)

    if what == CIC_FUNC:
        func = idaapi.get_func(ea)
        if func:
            return func.color
        else:
            return DEFCOLOR

    if what == CIC_SEGM:
        seg = idaapi.getseg(ea)
        if seg:
            return seg.color
        else:
            return DEFCOLOR

# color item codes:
CIC_ITEM = 1         # one instruction or data
CIC_FUNC = 2         # function
CIC_SEGM = 3         # segment

DEFCOLOR = 0xFFFFFFFF  # Default color


def SetColor(ea, what, color):
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
        return idaapi.set_item_color(ea, color)

    if what == CIC_FUNC:
        func = idaapi.get_func(ea)
        if func:
            func.color = color
            return bool(idaapi.update_func(func))
        else:
            return False

    if what == CIC_SEGM:
        seg = idaapi.getseg(ea)
        if seg:
            seg.color = color
            return bool(seg.update())
        else:
            return False


#--------------------------------------------------------------------------
#                               X M L
#--------------------------------------------------------------------------

def SetXML(path, name, value):
    """
    Set or update one or more XML values.

    @param path: XPath expression of elements where to create value(s)
    @param name: name of the element/attribute
                 (use @XXX for an attribute) to create.
                 If 'name' is empty, the elements or
                 attributes returned by XPath are directly
                 updated to contain the new 'value'.
    @param value: value of the element/attribute

    @return: success (True or False)
    """
    return idaapi.set_xml(path, name, value)


def GetXML(path):
    """
    Get one XML value.

    @param path: XPath expression to an element
                 or attribute whose value is requested

    @return: the value, None if failed
    """
    v = idaapi.value_t()
    if idaapi.get_xml(path):
        return v.str
    else:
        return None


#----------------------------------------------------------------------------
#                       A R M   S P E C I F I C
#----------------------------------------------------------------------------
def ArmForceBLJump(ea):
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
    return Eval("ArmForceBLJump(0x%x)"%ea)


def ArmForceBLCall(ea):
    """
    Force BL instruction to be a call

    @param ea: address of the BL instruction

    @return: 1-ok, 0-failed
    """
    return Eval("ArmForceBLCall(0x%x)"%ea)


#--------------------------------------------------------------------------
# Compatibility macros:
def Compile(file):           return CompileEx(file, 1)
def OpOffset(ea,base):       return OpOff(ea,-1,base)
def OpNum(ea):               return OpNumber(ea,-1)
def OpChar(ea):              return OpChr(ea,-1)
def OpSegment(ea):           return OpSeg(ea,-1)
def OpDec(ea):               return OpDecimal(ea,-1)
def OpAlt1(ea, opstr):       return OpAlt(ea, 0, opstr)
def OpAlt2(ea, opstr):       return OpAlt(ea, 1, opstr)
def StringStp(x):            return SetCharPrm(INF_ASCII_BREAK,x)
def LowVoids(x):             return SetLongPrm(INF_LOW_OFF,x)
def HighVoids(x):            return SetLongPrm(INF_HIGH_OFF,x)
def TailDepth(x):            return SetLongPrm(INF_MAXREF,x)
def Analysis(x):             return SetCharPrm(INF_AUTO,x)
def Tabs(x):                 return SetCharPrm(INF_ENTAB,x)
#def Comments(x):             SetCharPrm(INF_CMTFLAG,((x) ? (SW_ALLCMT|GetCharPrm(INF_CMTFLAG)) : (~SW_ALLCMT&GetCharPrm(INF_CMTFLAG))))
def Voids(x):                return SetCharPrm(INF_VOIDS,x)
def XrefShow(x):             return SetCharPrm(INF_XREFNUM,x)
def Indent(x):               return SetCharPrm(INF_INDENT,x)
def CmtIndent(x):            return SetCharPrm(INF_COMMENT,x)
def AutoShow(x):             return SetCharPrm(INF_SHOWAUTO,x)
def MinEA():                 return GetLongPrm(INF_MIN_EA)
def MaxEA():                 return GetLongPrm(INF_MAX_EA)
def BeginEA():               return GetLongPrm(INF_BEGIN_EA)
def set_start_cs(x):         return SetLongPrm(INF_START_CS,x)
def set_start_ip(x):         return SetLongPrm(INF_START_IP,x)

def WriteMap(filepath):
    return GenerateFile(OFILE_MAP, filepath, 0, BADADDR, GENFLG_MAPSEG|GENFLG_MAPNAME)

def WriteTxt(filepath, ea1, ea2):
    return GenerateFile(OFILE_ASM, filepath, ea1, ea2, 0)

def WriteExe(filepath):
    return GenerateFile(OFILE_EXE, filepath, 0, BADADDR, 0)


UTP_STRUCT = idaapi.UTP_STRUCT
UTP_ENUM   = idaapi.UTP_ENUM


def BeginTypeUpdating(utp):
    """
    Begin type updating. Use this function if you
    plan to call AddEnumConst or similar type modification functions
    many times or from inside a loop

    @param utp: one of UTP_xxxx consts
    @return: None
    """
    return idaapi.begin_type_updating(utp)


def EndTypeUpdating(utp):
    """
    End type updating. Refreshes the type system
    at the end of type modification operations

    @param utp: one of idaapi.UTP_xxxx consts
    @return: None
    """
    return idaapi.end_type_updating(utp)


def AddConst(enum_id, name,value): return AddConstEx(enum_id, name, value, idaapi.BADADDR)
def AddStruc(index, name):         return AddStrucEx(index,name, 0)
def AddUnion(index, name):         return AddStrucEx(index,name, 1)
def OpStroff(ea, n, strid):        return OpStroffEx(ea,n,strid, 0)
def OpEnum(ea, n, enumid):         return OpEnumEx(ea,n,enumid, 0)
def DelConst(constid, v, mask):    return DelConstEx(constid, v, 0, mask)
def GetConst(constid, v, mask):    return GetConstEx(constid, v, 0, mask)
def AnalyseArea(sEA, eEA):         return AnalyzeArea(sEA,eEA)

def MakeStruct(ea, name):                 return MakeStructEx(ea, -1, name)
def MakeCustomData(ea, size, dtid, fid):  return MakeCustomDataEx(ea, size, dtid, fid)
def Name(ea):                             return NameEx(BADADDR, ea)
def GetTrueName(ea):                      return GetTrueNameEx(BADADDR, ea)
def MakeName(ea, name):                   return MakeNameEx(ea,name,SN_CHECK)

#def GetFrame(ea):                return GetFunctionAttr(ea, FUNCATTR_FRAME)
#def GetFrameLvarSize(ea):        return GetFunctionAttr(ea, FUNCATTR_FRSIZE)
#def GetFrameRegsSize(ea):        return GetFunctionAttr(ea, FUNCATTR_FRREGS)
#def GetFrameArgsSize(ea):        return GetFunctionAttr(ea, FUNCATTR_ARGSIZE)
#def GetFunctionFlags(ea):        return GetFunctionAttr(ea, FUNCATTR_FLAGS)
#def SetFunctionFlags(ea, flags): return SetFunctionAttr(ea, FUNCATTR_FLAGS, flags)

#def SegStart(ea):                return GetSegmentAttr(ea, SEGATTR_START)
#def SegEnd(ea):                  return GetSegmentAttr(ea, SEGATTR_END)
#def SetSegmentType(ea, type):    return SetSegmentAttr(ea, SEGATTR_TYPE, type)

def SegCreate(a1, a2, base, use32, align, comb): return AddSeg(a1, a2, base, use32, align, comb)
def SegDelete(ea, flags):                        return DelSeg(ea, flags)
def SegBounds(ea, startea, endea, flags):        return SetSegBounds(ea, startea, endea, flags)
def SegRename(ea, name):                         return RenameSeg(ea, name)
def SegClass(ea, segclass):                      return SetSegClass(ea, segclass)
def SegAddrng(ea, bitness):                      return SetSegAddressing(ea, bitness)
def SegDefReg(ea, reg, value):                   return SetSegDefReg(ea, reg, value)


def Comment(ea):                return GetCommentEx(ea, 0)
"""Returns the regular comment or None"""

def RptCmt(ea):                 return GetCommentEx(ea, 1)
"""Returns the repeatable comment or None"""

def SetReg(ea, reg, value): return SetRegEx(ea, reg, value, SR_user)


# Convenience functions:
def here(): return ScreenEA()
def isEnabled(ea): return (PrevAddr(ea+1)==ea)

# Obsolete segdel macros:
SEGDEL_PERM   = 0x0001 # permanently, i.e. disable addresses
SEGDEL_KEEP   = 0x0002 # keep information (code & data, etc)
SEGDEL_SILENT = 0x0004 # be silent

ARGV = []
"""The command line arguments passed to IDA via the -S switch."""

# END OF IDC COMPATIBILY CODE
