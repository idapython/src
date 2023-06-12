"""
summary: custom painting on top of graph view edges

description:
  This sample registers an action enabling painting of a recognizable
  string of text over horizontal nodes edge sections beyond a
  satisfying size threshold.

  In a disassembly view, open the context menu and select
  "Paint on edges". This should work for both graph disassembly,
  and proximity browser.

  Using an "event filter", we will intercept paint events
  targeted at the disassembly view, let it paint itself, and
  then add our own markers along.
"""

from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets

import ida_graph
import ida_kernwin
import ida_moves

edge_segment_threshold = 50
text_color = QtGui.QColor(0, 0, 0)
text_antialiasing = True
verbose = False

class painter_t(QtCore.QObject):
    def __init__(self, w, verbose=False):
        QtCore.QObject.__init__(self)
        self.idaview = w
        self.idaview_pyqt = ida_kernwin.PluginForm.FormToPyQtWidget(w)
        self.target = self.idaview_pyqt.viewport()
        self.target.installEventFilter(self)
        self.painting = False

    def eventFilter(self, receiver, event):
        if not self.painting and \
           receiver == self.target and \
           event.type() == QtCore.QEvent.Paint:
            # Send a paint event that we won't intercept
            self.painting = True
            try:
                pev = QtGui.QPaintEvent(self.target.rect())
                QtWidgets.QApplication.instance().sendEvent(self.target, pev)
            finally:
                self.painting = False

            # now we can paint our items
            viewer = ida_graph.get_graph_viewer(self.idaview)
            graph = ida_graph.get_viewer_graph(viewer)
            if graph:
                painter = QtGui.QPainter(receiver)
                if text_antialiasing:
                    painter.setRenderHints(QtGui.QPainter.TextAntialiasing)
                else:
                    # this is primarily used for testing
                    font = painter.font()
                    font.setStyleStrategy(font.NoAntialias)
                    painter.setFont(font)
                painter.setPen(text_color)

                # The edge layout info we retrieve will be in "graph
                # coordinates". In order to transform those points to
                # view coordinates we will need the graph location info
                gli = ida_moves.graph_location_info_t()
                ida_graph.viewer_get_gli(gli, viewer);
                def to_view_coords(pt):
                    x = int((pt.x - gli.orgx) * gli.zoom)
                    y = int((pt.y - gli.orgy) * gli.zoom)
                    return ida_graph.point_t(x, y)

                # Let `src_node` be each visible node in the graph...
                for src_node in range(graph.size()):
                    if not graph.is_visible_node(src_node):
                        continue

                    # ...and `dst_node` be each visible node
                    # to which `src_node` is connected
                    for dst_node_idx in range(graph.nsucc(src_node)):
                        dst_node = graph.succ(src_node, dst_node_idx)
                        if not graph.is_visible_node(dst_node):
                            continue

                        edge_info = graph.get_edge(ida_graph.edge_t(src_node, dst_node))
                        if edge_info:

                            # For all horizontal edge segments satisfying the length requirements...
                            for idx in range(len(edge_info.layout)-1):
                                src = to_view_coords(edge_info.layout[idx])
                                dst = to_view_coords(edge_info.layout[idx+1])
                                if src.y == dst.y and abs(src.x - dst.x) > edge_segment_threshold:
                                    off = 6
                                    text = "%s -> %s (#%d)" % (src_node, dst_node, idx)
                                    if verbose:
                                        print("Painting \"%s\"" % text)
                                    painter.drawText(min(src.x, dst.x) + off, src.y - off, text)

                painter.end()

                # ...and prevent the widget form painting itself again
                return True
        return QtCore.QObject.eventFilter(self, receiver, event)

painter = None

class paint_on_edges_t(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        if self.get_idaview(ctx):
            global painter
            painter = painter_t(ctx.widget)
            return 1
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if self.get_idaview(ctx) \
               else ida_kernwin.AST_DISABLE_FOR_WIDGET

    def get_idaview(self, ctx):
        return ctx.widget if ctx.widget_type == ida_kernwin.BWN_DISASM else None

action_name = "paint_over_graph:enable"
ida_kernwin.register_action(
    ida_kernwin.action_desc_t(
        action_name,
        "Paint on edges",
        paint_on_edges_t()))

#
# Make sure our action is available for all disassembly views
#
class context_menu_hooks_t(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup, action_name, None)

hooks = context_menu_hooks_t()
hooks.hook()
