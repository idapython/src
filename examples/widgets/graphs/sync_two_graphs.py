"""
summary: follow the movements of a disassembly graph, in another.

description:
  Since it is possible to be notified of movements that happen
  take place in a widget, it's possible to "replay" those
  movements in another.

  In this case, "IDA View-B" (will be opened if necessary) will
  show the same contents as "IDA View-A", slightly zoomed out.

keywords: graph, idaview

see_also: wrap_idaview
"""

import ida_kernwin
import ida_moves
import ida_graph

#
# Cleanup (in case the script is run more than once)
#
try:
    wrap_a.Unbind()
except:
    pass


wrap_a = None

#
# The IDA View-A "monitor": changes will be reported into IDA View-B
#
class IDAViewA_monitor_t(ida_kernwin.IDAViewWrapper):
    def __init__(self):
        ida_kernwin.IDAViewWrapper.__init__(self, "IDA View-A")

    def OnViewLocationChanged(self, now, was):
        self.update_widget_b()

    def update_widget_b(self):

        # Make sure we are in the same function
        place_a, _, _ = ida_kernwin.get_custom_viewer_place(widget_a, False)
        ida_kernwin.jumpto(widget_b, place_a, -1, -1)

        # and that we show the right place (slightly zoomed out)
        widget_a_center_gli = ida_moves.graph_location_info_t()
        if ida_graph.viewer_get_gli(widget_a_center_gli, widget_a, ida_graph.GLICTL_CENTER):
            widget_b_center_gli = ida_moves.graph_location_info_t()
            widget_b_center_gli.orgx = widget_a_center_gli.orgx
            widget_b_center_gli.orgy = widget_a_center_gli.orgy
            widget_b_center_gli.zoom = widget_a_center_gli.zoom * 0.5
            ida_graph.viewer_set_gli(widget_b, widget_b_center_gli, ida_graph.GLICTL_CENTER)

#
# Make sure both views are opened...
#
for label in ["A", "B"]:
    title = "IDA View-%s" % label
    if not ida_kernwin.find_widget(title):
        print("View %s not available. Opening." % title)
        ida_kernwin.open_disasm_window(label)

#
# ...and that they are both in graph mode
#
widget_a = ida_kernwin.find_widget("IDA View-A")
ida_kernwin.set_view_renderer_type(widget_a, ida_kernwin.TCCRT_GRAPH)

widget_b = ida_kernwin.find_widget("IDA View-B")
ida_kernwin.set_view_renderer_type(widget_b, ida_kernwin.TCCRT_GRAPH)

#
# Put view B to the right of view A
#
ida_kernwin.set_dock_pos("IDA View-B", "IDA View-A", ida_kernwin.DP_RIGHT)

#
# Start monitoring IDA View-A
#
wrap_a = IDAViewA_monitor_t()
wrap_a.Bind()

#
# This is to get a properly initialized set of views to begin with.
# At this point, all UI resize/move events resulting of 'set_dock_pos()'
# haven't yet been processed, and thus the views don't know their final
# geometries. We'll give them a bit of time to process those events, and
# then we'll request that "IDA View-A" shows the whole graph (and
# "IDA View-B" will obviously follow.)
#
def fit_widget_a():
    def do_fit_widget_a():
        ida_graph.viewer_fit_window(widget_a)
    ida_kernwin.execute_sync(do_fit_widget_a, ida_kernwin.MFF_FAST)
import threading
threading.Timer(0.25, fit_widget_a).start()
