"""
A script to help you find desired opcodes/instructions in a database

The script accepts opcodes and assembly statements (which will be assembled) separated by semicolon

The general syntax is:
  find(asm or opcodes, x=Bool, asm_where=ea)

* Example:
  find("asm_statement1;asm_statement2;de ea dc 0d e0;asm_statement3;xx yy zz;...")
* To filter-out non-executable segments pass x=True
  find("jmp dword ptr [esp]", x=True)
* To specify in which context the instructions should be assembled, pass asm_where=ea:
  find("jmp dword ptr [esp]", asm_where=here())

Copyright (c) 1990-2024 Hex-Rays
ALL RIGHTS RESERVED.
"""
from __future__ import print_function
import re
import sys

import ida_idaapi
import ida_lines
import ida_segment
import ida_kernwin
import ida_bytes
import ida_ua
import ida_ida
import ida_search
import ida_funcs

import idautils

# -----------------------------------------------------------------------
def FindInstructions(instr, asm_where=None):
    """
    Finds instructions/opcodes
    @return: Returns a tuple(True, [ ea, ... ]) or a tuple(False, "error message")
    """
    if not asm_where:
        # get first segment
        seg = ida_segment.get_first_seg()
        asm_where = seg.start_ea if seg else ida_idaapi.BADADDR
        if asm_where == ida_idaapi.BADADDR:
            return (False, "No segments defined")

    # regular expression to distinguish between opcodes and instructions
    re_opcode = re.compile('^[0-9a-f]{2} *', re.I)

    # split lines
    lines = instr.split(";")

    # all the assembled buffers (for each instruction)
    bufs = []
    for line in lines:
        if re_opcode.match(line):
            # convert from hex string to a character list then join the list to form one string
            buf = bytes(bytearray([int(x, 16) for x in line.split()]))
        else:
            # assemble the instruction
            ret, buf = idautils.Assemble(asm_where, line)
            if not ret:
                return (False, "Failed to assemble:"+line)
        # add the assembled buffer
        bufs.append(buf)

    # join the buffer into one string
    buf = b''.join(bufs)

    # take total assembled instructions length
    tlen = len(buf)

    # convert from binary string to space separated hex string
    bin_str = ' '.join(["%02X" % (ord(x) if sys.version_info.major < 3 else x) for x in buf])

    # find all binary strings
    print("Searching for: [%s]" % bin_str)
    ea = ida_ida.cvar.inf.min_ea
    ret = []
    while True:
        ea = ida_search.find_binary(ea, ida_idaapi.BADADDR, bin_str, 16, ida_search.SEARCH_DOWN)
        if ea == ida_idaapi.BADADDR:
            break
        ret.append(ea)
        ida_kernwin.msg(".")
        ea += tlen
    if not ret:
        return (False, "Could not match [%s]" % bin_str)
    ida_kernwin.msg("\n")
    return (True, ret)

# -----------------------------------------------------------------------
# Chooser class
class SearchResultChoose(ida_kernwin.Choose):
    def __init__(self, title, items):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [["Address", 30], ["Function (or segment)", 25], ["Instruction", 20]],
            width=250)
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        i = self.items[n]
        ea = i.ea
        return [
            hex(i.ea),
            i.funcname_or_segname,
            i.text
        ]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.items[n].ea)

# -----------------------------------------------------------------------
# class to represent the results
class SearchResult:
    def __init__(self, ea):
        self.ea = ea
        self.funcname_or_segname = ""
        self.text = ""
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            ida_ua.create_insn(ea)

        # text
        t = ida_lines.generate_disasm_line(ea)
        if t:
            self.text = ida_lines.tag_remove(t)

        # funcname_or_segname
        n = ida_funcs.get_func_name(ea) \
            or ida_segment.get_segm_name(ida_segment.getseg(ea))
        if n:
            self.funcname_or_segname = n

# -----------------------------------------------------------------------
def find(s=None, x=False, asm_where=None):
    b, ret = FindInstructions(s, asm_where)
    if b:
        # executable segs only?
        if x:
            results = []
            for ea in ret:
                seg = ida_segment.getseg(ea)
                if (not seg) or (seg.perm & ida_segment.SEGPERM_EXEC) == 0:
                    continue
                results.append(SearchResult(ea))
        else:
            results = [SearchResult(ea) for ea in ret]
        title = "Search result for: [%s]" % s
        ida_kernwin.close_chooser(title)
        c = SearchResultChoose(title, results)
        c.Show(True)
    else:
        print(ret)

# -----------------------------------------------------------------------
print("Please use find('asm_stmt1;xx yy;...', x=Bool,asm_where=ea) to search for instructions or opcodes. Specify x=true to filter out non-executable segments")
