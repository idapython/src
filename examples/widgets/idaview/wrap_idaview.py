"""
summary: manipulate IDAView and graph

description:
  This is an example illustrating how to manipulate an existing IDA-provided
  view (and thus possibly its graph), in Python.

keywords: idaview, graph

see_also: custom_graph_with_actions, sync_two_graphs
"""

# -----------------------------------------------------------------------
# (c) Hex-Rays

from time import sleep
import threading

import ida_kernwin
import ida_graph

class Worker(threading.Thread):
    def __init__(self, w):
        threading.Thread.__init__(self)
        self.w = w

    def log(self, msg):
        print(">>> thread: %s" % msg)

    def req_SetCurrentRendererType(self, switch_to):
        w = self.w
        def f():
            self.log("Switching to %s" % switch_to)
            w.SetCurrentRendererType(switch_to)
        ida_kernwin.execute_sync(f, ida_kernwin.MFF_FAST)

    def req_SetNodeInfo(self, node, info, flags):
        w = self.w
        def f():
            self.log("Setting node info..")
            w.SetNodeInfo(node, info, flags)
        ida_kernwin.execute_sync(f, ida_kernwin.MFF_FAST)

    def req_DelNodesInfos(self, *nodes):
        w = self.w
        def f():
            self.log("Deleting nodes infos..")
            w.DelNodesInfos(*nodes)
        ida_kernwin.execute_sync(f, ida_kernwin.MFF_FAST)

    def run(self):
        # Note, in order to leave the UI available
        # to the user, we'll perform UI operations
        # in this thread.
        #
        # But.
        #
        # Qt expects that all UI operations be performed from
        # the main thread. Therefore, we'll have to use
        # 'ida_kernwin.execute_sync' to send requests to the main thread.

        # Switch back & forth to & from graph view
        for i in range(3):
            self.req_SetCurrentRendererType(ida_kernwin.TCCRT_FLAT)
            sleep(1)
            self.req_SetCurrentRendererType(ida_kernwin.TCCRT_GRAPH)
            sleep(1)

        # Go to graph view, and set the first node's color
        self.req_SetCurrentRendererType(ida_kernwin.TCCRT_GRAPH)
        ni = ida_graph.node_info_t()
        ni.bg_color    = 0x00ff00ff
        ni.frame_color = 0x0000ff00
        self.req_SetNodeInfo(0, ni, ida_graph.NIF_BG_COLOR|ida_graph.NIF_FRAME_COLOR)
        sleep(3)

        # This was fun. But let's revert it.
        self.req_DelNodesInfos(0)
        sleep(3)

        self.log("Done.")


class MyIDAViewWrapper(ida_kernwin.IDAViewWrapper):
    # A wrapper around the standard IDA view wrapper.
    # We'll react to some events and print the parameters
    # that were sent to us, that's all.
    def __init__(self, viewName):
        ida_kernwin.IDAViewWrapper.__init__(self, viewName)

    # Helper function, to be called by "On*" event handlers.
    # This will print all the arguments that were passed!
    def printPrevFrame(self):
        import inspect
        stack = inspect.stack()
        frame, _, _, _, _, _ = stack[1]
        args, _, _, values = inspect.getargvalues(frame)
        print("EVENT: %s: args=%s" % (
            inspect.getframeinfo(frame)[2],
            [(i, values[i]) for i in args[1:]]))

    def OnViewKeydown(self, key, state):
        self.printPrevFrame()

    def OnViewClick(self, x, y, state):
        self.printPrevFrame()

    def OnViewDblclick(self, x, y, state):
        self.printPrevFrame()

    def OnViewSwitched(self, rt):
        self.printPrevFrame()

    def OnViewMouseOver(self, x, y, state, over_type, over_data):
        self.printPrevFrame()



viewName = "IDA View-A"
w = MyIDAViewWrapper(viewName)
if w.Bind():
    print("Succesfully bound to %s" % viewName)

    # We'll launch the sequence of operations in another thread,
    # so that sleep() calls don't freeze the UI
    worker = Worker(w)
    worker.start()

else:
    print("Couldn't bind to view %s. Is it available?" % viewName)
