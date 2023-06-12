"""
summary: custom painting on top of the navigation band

description:
  Using an "event filter", we will intercept paint events
  targeted at the navigation band widget, let it paint itself,
  and then add our own markers on top.
"""

import random

from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets

import ida_kernwin
import ida_segment

import idc

class painter_t(QtCore.QObject):
    def __init__(self):
        QtCore.QObject.__init__(self)
        self.target = ida_kernwin.PluginForm.FormToPyQtWidget(ida_kernwin.open_navband_window(idc.here(), 1))
        self.target.installEventFilter(self)
        self.items = []
        self.painting = False

    def add_item(self, ea, radius, color):
        self.items.append((ea, radius, color))
        self.target.update()

    def add_random_item(self):
        R = random.random
        s = ida_segment.getnseg(int(ida_segment.get_segm_qty() * R()))
        ea = s.start_ea + int((s.end_ea - s.start_ea) * R())
        radius = 4 + int(R() * 8)
        color = QtGui.QColor(int(255 * R()), int(255 * R()), int(255 * R()))
        self.add_item(ea, radius, color)

    def eventFilter(self, receiver, event):
        if not self.painting and \
           self.target == receiver and \
           event.type() == QtCore.QEvent.Paint:

            # Send a paint event that we won't intercept
            self.painting = True
            try:
                pev = QtGui.QPaintEvent(self.target.rect())
                QtWidgets.QApplication.instance().sendEvent(self.target, pev)
            finally:
                self.painting = False

            # now we can paint our items
            for ea, radius, color in self.items:
                painter = QtGui.QPainter(receiver)
                painter.setRenderHints(QtGui.QPainter.Antialiasing)
                pxl, is_vertical = ida_kernwin.get_navband_pixel(ea)
                if pxl >= 0:
                    x = (self.target.width() // 2) if is_vertical else pxl
                    y = pxl if is_vertical else (self.target.height() // 2)
                    painter.setPen(color)
                    painter.setBrush(color)
                    painter.drawEllipse(QtCore.QPoint(x, y), radius, radius)
                painter.end()

            # ...and prevent the widget form painting itself again
            return True
        return QtCore.QObject.eventFilter(self, receiver, event)

painter = painter_t()

# Try the following:
# for i in range(100): painter.add_random_item()
