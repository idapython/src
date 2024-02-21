"""

A script that tries to determine the call stack

Run the application with the debugger, suspend the debugger, select a thread and finally run the script.

Copyright (c) 1990-2024 Hex-Rays
ALL RIGHTS RESERVED.
"""
import ida_ua
import ida_bytes
import ida_kernwin
import ida_funcs
import ida_name
import ida_ida
import ida_idp
import ida_segment
import ida_dbg
import idautils

# -----------------------------------------------------------------------
# class to take a copy of a segment_t
class Seg():
    def __init__(self, s):
        self.start_ea = s.start_ea
        self.end_ea   = s.end_ea
        self.perm     = s.perm
        self.bitness  = s.bitness

    def __cmp__(self, other):
        return cmp(self.start_ea, other.start_ea)

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
    if ea == ida_idaapi.BADADDR or ea < 10:
        return None

    for delta, opcodes in CallPattern:
        # assume caller's ea
        caller = ea + delta
        # get the bytes
        bytes = [x for x in idautils.GetDataList(caller, len(opcodes), 1)]
        # do we have a match? is it a call instruction?
        if bytes == opcodes:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, caller) and ida_idp.is_call_insn(insn):
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
            f = ida_funcs.get_func(caller)
            self.displ = "%08x: " % caller
            if f:
                self.displ += ida_funcs.get_func_name(caller)
                t = caller - f.start_ea
                if t > 0: self.displ += "+" + hex(t)
            else:
                self.displ += hex(caller)
            self.displ += " [" + hex(sp) + "]"

        def __str__(self):
            return self.displ

    # get stack pointer
    sp = idautils.cpu.Esp
    seg = ida_segment.getseg(sp)
    if not seg:
        return (False, "Could not locate stack segment!")

    stack_seg = Seg(seg)
    word_size = 2 ** (seg.bitness + 1)
    callers = []
    sp = idautils.cpu.Esp - word_size
    while sp < stack_seg.end_ea:
        sp += word_size
        ptr = next(idautils.GetDataList(sp, 1, word_size))
        seg = ida_segment.getseg(ptr)
        # only accept executable segments
        if (not seg) or ((seg.perm & ida_segment.SEGPERM_EXEC) == 0):
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
                f = ida_funcs.get_func(ea)
                if not f:
                    # create function
                    ida_funcs.add_func(ea)

        # get the flags
        f = ida_bytes.get_flags(caller)
        # no code there?
        if not ida_bytes.is_code(f):
            ida_ua.create_insn(caller)

        callers.append(Result(caller, sp))
    #
    return (True, callers)

# -----------------------------------------------------------------------
# Chooser class
class CallStackWalkChoose(ida_kernwin.Choose):
    def __init__(self, title, items):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [["Location", 30]])
        self.items = items
        self.modal = True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return [str(self.items[n])]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.items[n].caller)

# -----------------------------------------------------------------------
def main():
    if not ida_dbg.is_debugger_on():
        ida_kernwin.warning("Please run the process first!")
        return
    if ida_dbg.get_process_state() != -1:
        ida_kernwin.warning("Please suspend the debugger first!")
        return

    # get all debug namesp
    dn = ida_name.get_debug_names(ida_ida.cvar.inf.min_ea, ida_ida.cvar.inf.max_ea)
    # initiate a nearest name search (using debug names)
    nn = ida_name.NearestName(dn)

    ret, callstack = CallStackWalk(nn)
    if ret:
        title = "Call stack walker (thread %X)" % (ida_dbg.get_current_thread())
        ida_kernwin.close_chooser(title)
        c = CallStackWalkChoose(title, callstack)
        c.Show(True)
    else:
        ida_kernwin.warning("Failed to walk the stack:" + callstack)

# -----------------------------------------------------------------------
main()
