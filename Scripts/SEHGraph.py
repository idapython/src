"""

A script that graphs all the exception handlers in a given process

It will be easy to see what thread uses what handler and what handlers are commonly used between threads

Copyright (c) 1990-2024 Hex-Rays
ALL RIGHTS RESERVED.
"""
from __future__ import print_function

import ida_kernwin
import ida_graph
import ida_idd
import ida_dbg
import ida_funcs

import idautils

# -----------------------------------------------------------------------
# Since Windbg debug module does not support get_thread_sreg_base()
# we will call the debugger engine "dg" command and parse its output
def WindbgGetRegBase(tid):
    ok, s = ida_dbg.send_dbg_command("dg %x" % idautils.cpu.fs)
    if not ok:
        return 0
    m = re.compile("[0-9a-f]{4} ([0-9a-f]{8})")
    t = m.match(s.split('\n')[-2])
    if not t:
        return 0
    return int(t.group(1), 16)

# -----------------------------------------------------------------------
def GetFsBase(tid):
    ida_dbg.select_thread(tid)
    base = ida_idd.dbg_get_thread_sreg_base(tid, idautils.cpu.fs)
    if base != 0:
      return base
    return WindbgGetRegBase(tid)

# -----------------------------------------------------------------------
# Walks the SEH chain and returns a list of handlers
def GetExceptionChain(tid):
    fs_base = GetFsBase(tid)
    print("FS_BASE for %s: %s (cpu.fs=%s)" % (repr(tid), repr(fs_base), repr(idautils.cpu.fs)))
    exc_rr = ida_bytes.get_wide_dword(fs_base)
    result = []
    while exc_rr != 0xffffffff:
        prev    = get_wide_dword(exc_rr)
        handler = get_wide_dword(exc_rr + 4)
        exc_rr  = prev
        result.append(handler)
    return result

# -----------------------------------------------------------------------
class SEHGraph(ida_graph.GraphViewer):
    def __init__(self, title, result):
        ida_graph.GraphViewer.__init__(self, title)
        self.result = result
        self.names  = {} # ea -> name

    def OnRefresh(self):
        self.Clear()
        addr_id = {}

        for (tid, chain) in self.result.items():
            # Each node data will contain a tuple of the form: (Boolean->Is_thread, Int->Value, String->Label)
            # For threads the is_thread will be true and the value will hold the thread id
            # For exception handlers, is_thread=False and Value=Handler address

            # Add the thread node
            id_parent = self.AddNode( (True, tid, "Thread %X" % tid) )

            # Add each handler
            for handler in chain:
              # Check if a function is created at the handler's address
              f = ida_funcs.get_func(handler)
              if not f:
                  # create function
                  ida_funcs.add_func(handler)

              # Node label is function name or address
              s = ida_funcs.get_func_name(handler)
              if not s:
                  s = "%x" % handler

              # cache name
              self.names[handler] = s

              # Get the node id given the handler address
              # We use an addr -> id dictionary so that similar addresses get similar node id
              if handler not in addr_id:
                  id = self.AddNode( (False, handler, s) )
                  addr_id[handler] = id # add this ID
              else:
                  id = addr_id[handler]

              # Link handlers to each other
              self.AddEdge(id_parent, id)
              id_parent = id

        return True

    def OnGetText(self, node_id):
        is_thread, value, label = self[node_id]
        if is_thread:
            return (label, 0xff00f0)
        return label

    def OnDblClick(self, node_id):
        is_thread, value, label = self[node_id]
        if is_thread:
            ida_dbg.select_thread(value)
            self.Show()
            s = "SEH chain for " + hex(value)
            t = "-" * len(s)
            print(t)
            print(s)
            print(t)
            for handler in self.result[value]:
                print("%x: %s" % (handler, self.names[handler]))
            print(t)
        else:
            ida_kernwin.jumpto(value)
        return True


# -----------------------------------------------------------------------
def main():
    if not ida_idd.dbg_can_query():
        print("The debugger must be active and suspended before using this script!")
        return

    # Save current thread id
    tid = ida_dbg.get_current_thread()

    # Iterate through all function instructions and take only call instructions
    result = {}
    for tid in idautils.Threads():
        result[tid] = GetExceptionChain(tid)

    # Restore previously selected thread
    ida_dbg.select_thread(tid)

    # Build the graph
    g = SEHGraph("SEH graph", result)
    g.Show()

main()
