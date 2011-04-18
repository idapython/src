"""
FindInstructions.py: A script to help you find desired opcodes/instructions in a database

The script accepts opcodes and assembly statements (which will be assembled) separated by semicolon

The general syntax is:
  find(asm or opcodes, x=Bool, asm_where=ea)

* Example:
  find("asm_statement1;asm_statement2;de ea dc 0d e0;asm_statement3;xx yy zz;...")
* To filter-out non-executable segments pass x=True
  find("jmp dword ptr [esp]", x=True)
* To specify in which context the instructions should be assembled, pass asm_where=ea:
  find("jmp dword ptr [esp]", asm_where=here())

Copyright (c) 1990-2009 Hex-Rays
ALL RIGHTS RESERVED.

v1.0 - initial version
"""
import idaapi
import idautils
import idc

# -----------------------------------------------------------------------
def FindInstructions(instr, asm_where=None):
    """
    Finds instructions/opcodes
    @return: Returns a tuple(True, [ ea, ... ]) or a tuple(False, "error message")
    """
    if not asm_where:
        # get first segment
        asm_where = FirstSeg()
        if asm_where == idaapi.BADADDR:
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
            buf = ''.join([chr(int(x, 16)) for x in line.split()])
        else:
            # assemble the instruction
            ret, buf = Assemble(asm_where, line)
            if not ret:
                return (False, "Failed to assemble:"+line)
        # add the assembled buffer
        bufs.append(buf)

    # join the buffer into one string
    buf = ''.join(bufs)
    
    # take total assembled instructions length
    tlen = len(buf)

    # convert from binary string to space separated hex string
    bin_str = ' '.join(["%02X" % ord(x) for x in buf])

    # find all binary strings
    print "Searching for: [%s]" % bin_str
    ea = MinEA()
    ret = []
    while True:
        ea = FindBinary(ea, SEARCH_DOWN, bin_str)
        if ea == idaapi.BADADDR:
            break
        ret.append(ea)
        Message(".")
        ea += tlen
    if not ret:
        return (False, "Could not match [%s]" % bin_str)
    Message("\n")
    return (True, ret)

# -----------------------------------------------------------------------
# Chooser class
class SearchResultChoose(Choose):
    def __init__(self, list, title):
        Choose.__init__(self, list, title)
        self.width = 250

    def enter(self, n):
        o = self.list[n-1]
        Jump(o.ea)

# -----------------------------------------------------------------------
# class to represent the results
class SearchResult:
    def __init__(self, ea):
        self.ea = ea
        if not isCode(GetFlags(ea)):
            MakeCode(ea)
        t = idaapi.generate_disasm_line(ea)
        if t:
            line = idaapi.tag_remove(t)
        else:
            line = ""
        func = GetFunctionName(ea)
        self.display = hex(ea) + ": "
        if func:
            self.display += func + ": "
        else:
            n = SegName(ea)
            if n: self.display += n + ": "
        self.display += line

    def __str__(self):
        return self.display

# -----------------------------------------------------------------------
def find(s=None, x=False, asm_where=None):
    b, ret = FindInstructions(s, asm_where)
    if b:
        # executable segs only?
        if x:
            results = []
            for ea in ret:
                seg = idaapi.getseg(ea)
                if (not seg) or (seg.perm & idaapi.SEGPERM_EXEC) == 0:
                    continue
                results.append(SearchResult(ea))
        else:
            results = [SearchResult(ea) for ea in ret]
        title = "Search result for: [%s]" % s
        idaapi.close_chooser(title)
        c = SearchResultChoose(results, title)
        c.choose()
    else:
        print ret

# -----------------------------------------------------------------------
print "Please use find('asm_stmt1;xx yy;...', x=Bool,asm_where=ea) to search for instructions or opcodes. Specify x=true to filter out non-executable segments"
