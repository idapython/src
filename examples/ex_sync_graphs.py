
from idaapi import *

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
class IDAViewA_monitor_t(IDAViewWrapper):
    def __init__(self):
        IDAViewWrapper.__init__(self, "IDA View-A")

    def OnViewLocationChanged(self, now, was):
        self.update_widget_b()

    def update_widget_b(self):

        # Make sure we are in the same function
        place_a, _, _ = get_custom_viewer_place(widget_a, False)
        jumpto(widget_b, place_a, -1, -1)

        # and that we show the right place (slightly zoomed out)
        widget_a_center_gli = graph_location_info_t()
        if viewer_get_gli(widget_a_center_gli, widget_a, GLICTL_CENTER):
            widget_b_center_gli = graph_location_info_t()
            widget_b_center_gli.orgx = widget_a_center_gli.orgx
            widget_b_center_gli.orgy = widget_a_center_gli.orgy
            widget_b_center_gli.zoom = widget_a_center_gli.zoom * 0.5
            viewer_set_gli(widget_b, widget_b_center_gli, GLICTL_CENTER)

#
# Make sure both views are opened...
#
for label in ["A", "B"]:
    title = "IDA View-%s" % label
    if not find_widget(title):
        print("View %s not available. Opening." % title)
        open_disasm_window(label)

#
# ...and that they are both in graph mode
#
widget_a = find_widget("IDA View-A")
set_view_renderer_type(widget_a, TCCRT_GRAPH)

widget_b = find_widget("IDA View-B")
set_view_renderer_type(widget_b, TCCRT_GRAPH)

#
# Put view B to the right of view A
#
set_dock_pos("IDA View-B", "IDA View-A", DP_RIGHT)

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
        viewer_fit_window(widget_a)
    execute_sync(do_fit_widget_a, MFF_FAST)
import threading
threading.Timer(0.25, fit_widget_a).start()
