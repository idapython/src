#------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler Pro
#
# Copyright (c) 2004-2008 Gergely Erdelyi <dyce@d-dome.net> 
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#------------------------------------------------------------
"""
idautils.py - High level utility functions for IDA
"""
import idaapi

def refs(ea, funcfirst, funcnext):
    """
    Generic reference collector - INTERNAL USE ONLY.
    """
    reflist = []

    ref = funcfirst(ea)

    if ref != idaapi.BADADDR:
        reflist.append(ref)

        while 1:
            ref = funcnext(ea, ref)

            if ref == idaapi.BADADDR:
                break
            else:
                reflist.append(ref)
    
    return reflist
    

def CodeRefsTo(ea, flow):
    """
    Get a list of code references to 'ea'

    @param ea:   Target address
    @param flow: Follow normal code flow or not 
    @type  flow: Boolean (0/1, False/True)

    @return: list of references (may be empty list)

    Example::
    
        for ref in CodeRefsTo(ScreenEA(), 1):
            print ref
    """
    if flow == 1:
        return refs(ea, idaapi.get_first_cref_to, idaapi.get_next_cref_to)    
    else:
        return refs(ea, idaapi.get_first_fcref_to, idaapi.get_next_fcref_to)    


def CodeRefsFrom(ea, flow):
    """
    Get a list of code references from 'ea'

    @param ea:   Target address
    @param flow: Follow normal code flow or not 
    @type  flow: Boolean (0/1, False/True)

    @return: list of references (may be empty list)

    Example::
    
        for ref in CodeRefsFrom(ScreenEA(), 1):
            print ref
    """
    if flow == 1:
        return refs(ea, idaapi.get_first_cref_from, idaapi.get_next_cref_from)    
    else:
        return refs(ea, idaapi.get_first_fcref_from, idaapi.get_next_fcref_from)    


def DataRefsTo(ea):
    """
    Get a list of data references to 'ea'

    @param ea:   Target address

    @return: list of references (may be empty list)

    Example::
    
        for ref in DataRefsTo(ScreenEA(), 1):
            print ref
    """
    return refs(ea, idaapi.get_first_dref_to, idaapi.get_next_dref_to)    


def DataRefsFrom(ea):
    """
    Get a list of data references from 'ea'

    @param ea:   Target address

    @return: list of references (may be empty list)

    Example::
    
        for ref in DataRefsFrom(ScreenEA(), 1):
            print ref
    """
    return refs(ea, idaapi.get_first_dref_from, idaapi.get_next_dref_from)    


def XrefTypeName(typecode):
    """
    Convert cross-reference type codes to readable names

    @param typecode: cross-reference type code
    """
    ref_types = { 
        0  : 'Data_Unknown',
        1  : 'Data_Offset', 
        2  : 'Data_Write',
        3  : 'Data_Read',
        4  : 'Data_Text',
        5  : 'Data_Informational',
        16 : 'Code_Far_Call',
        17 : 'Code_Near_Call',
        18 : 'Code_Far_Jump',
        19 : 'Code_Near_Jump',
        20 : 'Code_User',
        21 : 'Ordinary_Flow'
        }
    assert typecode in ref_types, "unknown reference type %d" % typecode
    return ref_types[typecode]


def XrefsFrom(ea, flags=0):
    """ 
    Return all references from address 'ea'
    
    @param ea: Reference address
    @param flags: any of idaapi.XREF_* flags

    Example:
           for xref in XrefsFrom(here(), 0):
               print xref.type, XrefTypeName(xref.type), \
                         'from', hex(xref.frm), 'to', hex(xref.to)

    """
    xref = idaapi.xrefblk_t()
    if xref.first_from(ea, flags):
        yield xref
        while xref.next_from():
            yield xref


def XrefsTo(ea, flags=0):
    """
    Return all references to address 'ea'
    
    @param ea: Reference address
    @param flags: any of idaapi.XREF_* flags

    Example:
           for xref in XrefsTo(here(), 0):
               print xref.type, XrefTypeName(xref.type), \
                         'from', hex(xref.frm), 'to', hex(xref.to)
    """
    xref = idaapi.xrefblk_t()
    if xref.first_to(ea, flags):
        yield xref
        while xref.next_to():
            yield xref


def Heads(start, end):
    """
    Get a list of heads (instructions or data)

    @param start: start address (this one is always included)
    @param end:   end address

    @return: list of heads between start and end
    """
    headlist = []
    headlist.append(start)

    ea = start

    while 1:
        ea = idaapi.next_head(ea, end)

        if ea == idaapi.BADADDR:
            break
        else:
            headlist.append(ea)
    
    return headlist
    

def Functions(start, end):
    """
    Get a list of functions

    @param start: start address
    @param end:   end address

    @return: list of heads between start and end

    @note: The last function that starts before 'end' is included even
    if it extends beyond 'end'.
    """
    startaddr = start
    endaddr = end

    funclist = []

    func = idaapi.get_func(start)

    if func:
        funclist.append(func.startEA)

    ea = start

    while 1:
        func = idaapi.get_next_func(ea)

        if not func: break

        if func.startEA < end:
            funclist.append(func.startEA)
            ea = func.startEA
        else:
            break

    return funclist
    

def Chunks(start):
    """
    Get a list of function chunks

    @param start: address of the function
       
    @return: list of funcion chunks (tuples of the form (start_ea, end_ea))
             belonging to the function
    """
    function_chunks = []

    func_iter = idaapi.func_tail_iterator_t( idaapi.get_func( start ) )
    status = func_iter.main()

    while status:
        chunk = func_iter.chunk()
        function_chunks.append((chunk.startEA, chunk.endEA))
        status = func_iter.next()

    return function_chunks


def Segments():
    """
    Get list of segments (sections) in the binary image

    @return: List of segment start addresses.
    """
    seglist = []

    for n in range(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(n)

        if not seg:
            break
        else:
            seglist.append(seg.startEA)
    
    return seglist


def GetDataList(ea, count, itemsize=1):
    """
    Get data list - INTERNAL USE ONLY
    """
    getdata = None

    if itemsize == 1:
        getdata = idaapi.get_byte
    if itemsize == 2:
        getdata = idaapi.get_word
    if itemsize == 4:
        getdata = idaapi.get_dword

    if getdata == None:
        raise ValueError, "Invalid data size! Must be 1, 2 or 4"

    list = []

    for offs in range(count):
        list.append(getdata(ea))
        ea = ea + itemsize

    return list


def PutDataList(ea, list, itemsize=1):
    """
    Put data list - INTERNAL USE ONLY
    """
    putdata = None

    if itemsize == 1:
        putdata = idaapi.patch_byte
    if itemsize == 2:
        putdata = idaapi.patch_word
    if itemsize == 4:
        putdata = idaapi.patch_dword

    if putdata == None:
        raise ValueError, "Invalid data size! Must be 1, 2 or 4"

    for val in list:
        putdata(ea, val)
        ea = ea + itemsize


def MapDataList(ea, length, func, wordsize=1):
    """
    Map through a list of data words in the database

    @param ea:       start address
    @param length:   number of words to map
    @param func:     mapping function
    @param wordsize: size of words to map [default: 1 byte]

    @return: None
    """
    PutDataList(ea, map(func, GetDataList(ea, length, wordsize)), wordsize)


def GetInputFileMD5():
    """
    Return the MD5 hash of the input binary file

    @return: MD5 string or None on error
    """
    ua=idaapi.ucharArray(16)
    if idaapi.retrieve_input_file_md5(ua.cast()):
        md5str=""
        for i in range(16):
            md5str += "%02x" % ua[i]
        return md5str
    else:
        return None

