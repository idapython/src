"""

A script that tries to determine the call stack

Run the application with the debugger, suspend the debugger, select a thread and finally run the script.

Copyright (c) 1990-2009 Hex-Rays
ALL RIGHTS RESERVED.


v1.0 - initial version
v1.0.1 - added stack segment bitness detection, thus works with 64bit processes too
"""
import idaapi
import idc
import idautils

# -----------------------------------------------------------------------
# class to take a copy of a segment_t
class Seg():
    def __init__(self, s):
        self.startEA = s.startEA
        self.endEA   = s.endEA
        self.perm    = s.perm
        self.bitness = s.bitness
    def __cmp__(self, other):
        return cmp(self.startEA, other.startEA)

# -----------------------------------------------------------------------
# each item described as:
# [ delta, [ opcode(s) ] ]
#FF10             call        d,[eax]
#FF5000           call        d,[eax][0]
#FF9044332211     call        d,[eax][011223344]
#FF1500000100     call        d,[000010000]
#FF9300000000     call        d,[ebx][0]
#FF10             call        d,[eax]
CallPattern = \
[
    [-2, [0xFF] ],
    [-3, [0xFF] ],
    [-5, [0xE8] ],
    [-6, [0xFF] ],
]

# -----------------------------------------------------------------------
def IsPrevInsnCall(ea):
    """
    Given a return address, this function tries to check if previous instruction
    is a CALL instruction
    """
    global CallPattern
    if ea == idaapi.BADADDR or ea < 10:
        return None

    for delta, opcodes in CallPattern:
        # assume caller's ea
        caller = ea + delta
        # get the bytes
        bytes = [x for x in GetDataList(caller, len(opcodes), 1)]
        # do we have a match? is it a call instruction?
        if bytes == opcodes and idaapi.is_call_insn(caller):
            return caller
    return None

# -----------------------------------------------------------------------
def CallStackWalk(nn):
    class Result:
        """
        Class holding the result of one call stack item
        Each call stack item instance has the following attributes:
            caller = ea of caller
            displ  = display string
            sp     = stack pointer
        """
        def __init__(self, caller, sp):
            self.caller = caller
            self.sp     = sp
            f = idaapi.get_func(caller)
            self.displ = "%08x: " % caller
            if f:
                self.displ += idc.GetFunctionName(caller)
                t = caller - f.startEA
                if t > 0: self.displ += "+" + hex(t)
            else:
                self.displ += hex(caller)
            self.displ += " [" + hex(sp) + "]"

        def __str__(self):
            return self.displ

    # get stack pointer
    sp = cpu.Esp
    seg = idaapi.getseg(sp)
    if not seg:
        return (False, "Could not locate stack segment!")

    stack_seg = Seg(seg)
    word_size = 2 ** (seg.bitness + 1)
    callers = []
    sp = cpu.Esp - word_size
    while sp < stack_seg.endEA:
        sp += word_size
        ptr = idautils.GetDataList(sp, 1, word_size).next()
        seg = idaapi.getseg(ptr)
        # only accept executable segments
        if (not seg) or ((seg.perm & idaapi.SEGPERM_EXEC) == 0):
            continue
        # try to find caller
        caller = IsPrevInsnCall(ptr)
        # we have no recognized caller, skip!
        if caller is None:
            continue

        # do we have a debug name that is near?
        if nn:
            ret = nn.find(caller)
            if ret:
                ea = ret[0]
                # function exists?
                f = idaapi.get_func(ea)
                if not f:
                    # create function
                    idc.MakeFunction(ea, idaapi.BADADDR)

        # get the flags
        f = idc.GetFlags(caller)
        # no code there?
        if not isCode(f):
            MakeCode(caller)

        callers.append(Result(caller, sp))
    #
    return (True, callers)

# -----------------------------------------------------------------------
# Chooser class
class CallStackWalkChoose(Choose):
    def __init__(self, list, title):
        Choose.__init__(self, list, title)
        self.width = 250

    def enter(self, n):
        o = self.list[n-1]
        idc.Jump(o.caller)

# -----------------------------------------------------------------------
def main():
    if not idaapi.is_debugger_on():
        idc.Warning("Please run the process first!")
        return
    if idaapi.get_process_state() != -1:
        idc.Warning("Please suspend the debugger first!")
        return

    # only avail from IdaPython r232
    if hasattr(idaapi, "NearestName"):
        # get all debug names
        dn = idaapi.get_debug_names(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA)
        # initiate a nearest name search (using debug names)
        nn = idaapi.NearestName(dn)
    else:
        nn = None

    ret, callstack = CallStackWalk(nn)
    if ret:
        title = "Call stack walker (thread %X)" % (GetCurrentThreadId())
        idaapi.close_chooser(title)
        c = CallStackWalkChoose(callstack, title)
        c.choose()
    else:
        idc.Warning("Failed to walk the stack:" + callstack)

# -----------------------------------------------------------------------
main()