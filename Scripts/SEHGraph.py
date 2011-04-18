"""

A script that graphs all the exception handlers in a given process

It will be easy to see what thread uses what handler and what handlers are commonly used between threads

Copyright (c) 1990-2009 Hex-Rays
ALL RIGHTS RESERVED.


v1.0 - initial version

"""

import idaapi
import idautils
import idc

from idaapi import GraphViewer

# -----------------------------------------------------------------------
# Since Windbg debug module does not support get_thread_sreg_base()
# we will call the debugger engine "dg" command and parse its output
def WindbgGetRegBase(tid):
    s = idc.Eval('WinDbgCommand("dg %x")' % cpu.fs)
    if "IDC_FAILURE" in s:
        return 0
    m = re.compile("[0-9a-f]{4} ([0-9a-f]{8})")
    t = m.match(s.split('\n')[-2])
    if not t:
        return 0
    return int(t.group(1), 16)

# -----------------------------------------------------------------------
def GetFsBase(tid):
    idc.SelectThread(tid)
    base = idaapi.dbg_get_thread_sreg_base(tid, cpu.fs)
    if base != 0:
      return base
    return WindbgGetRegBase(tid)

# -----------------------------------------------------------------------
# Walks the SEH chain and returns a list of handlers
def GetExceptionChain(tid):
    fs_base = GetFsBase(tid)
    exc_rr = Dword(fs_base)
    result = []
    while exc_rr != 0xffffffff:
        prev    = Dword(exc_rr)
        handler = Dword(exc_rr + 4)
        exc_rr  = prev
        result.append(handler)
    return result

# -----------------------------------------------------------------------
class SEHGraph(GraphViewer):
    def __init__(self, title, result):
        GraphViewer.__init__(self, title)
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
              f = idaapi.get_func(handler)
              if not f:
                  # create function
                  idc.MakeFunction(handler, idaapi.BADADDR)

              # Node label is function name or address
              s = GetFunctionName(handler)
              if not s:
                  s = "%x" % handler

              # cache name
              self.names[handler] = s

              # Get the node id given the handler address
              # We use an addr -> id dictionary so that similar addresses get similar node id
              if not addr_id.has_key(handler):
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
            idc.SelectThread(value)
            self.Show()
            s = "SEH chain for " + hex(value)
            t = "-" * len(s)
            print t
            print s
            print t
            for handler in self.result[value]:
                print "%x: %s" % (handler, self.names[handler])
            print t
        else:
            idc.Jump(value)
        return True


# -----------------------------------------------------------------------
def main():
    if not idaapi.dbg_can_query():
        print "The debugger must be active and suspended before using this script!"
        return

    # Save current thread id
    tid = GetCurrentThreadId()

    # Iterate through all function instructions and take only call instructions
    result = {}
    for tid in idautils.Threads():
        result[tid] = GetExceptionChain(tid)

    # Restore previously selected thread
    idc.SelectThread(tid)

    # Build the graph
    g = SEHGraph("SEH graph", result)
    g.Show()

main()
