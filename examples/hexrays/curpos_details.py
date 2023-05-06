"""
summary: a focus on the 'curpos' hook, printing additional details about user input

description:
  Shows how user input information can be retrieved during
  processing of a notification triggered by that input

see_also: vds_hooks
"""

import ida_hexrays
import ida_kernwin

class curpos_details_t(ida_hexrays.Hexrays_Hooks):
    def curpos(self, v):
        parts = ["cpos={lnnum=%d, x=%d, y=%d}" % (v.cpos.lnnum, v.cpos.x, v.cpos.y)]
        uie = ida_kernwin.input_event_t()
        if ida_kernwin.get_user_input_event(uie):
            kind_str = {
                ida_kernwin.iek_shortcut : "shortcut",
                ida_kernwin.iek_key_press : "key_press",
                ida_kernwin.iek_key_release : "key_release",
                ida_kernwin.iek_mouse_button_press : "mouse_button_press",
                ida_kernwin.iek_mouse_button_release : "mouse_button_release",
                ida_kernwin.iek_mouse_wheel : "mouse_wheel",
            }[uie.kind]

            #
            # Retrieve input kind-specific information
            #
            if uie.kind == ida_kernwin.iek_shortcut:
                payload_str = "shortcut={action_name=%s}" % uie.shortcut.action_name
            elif uie.kind in [
                    ida_kernwin.iek_key_press,
                    ida_kernwin.iek_key_release]:
                payload_str = "keyboard={key=%d, text=%s}" % (uie.keyboard.key, uie.keyboard.text)
            else:
                payload_str = "mouse={x=%d, y=%d, button=%d}" % (
                    uie.mouse.x,
                    uie.mouse.y,
                    uie.mouse.button)

            #
            # And while at it, retrieve a few extra bits from the
            # source QEvent as well, why not
            #
            qevent = uie.get_source_QEvent()
            qevent_str = str(qevent)
            from PyQt5 import QtCore
            if qevent.type() in [
                    QtCore.QEvent.KeyPress,
                    QtCore.QEvent.KeyRelease]:
                qevent_str="{count=%d}" % qevent.count()
            elif qevent.type() in [
                    QtCore.QEvent.MouseButtonPress,
                    QtCore.QEvent.MouseButtonRelease]:
                qevent_str="{globalX=%d, globalY=%d, flags=%s}" % (
                    qevent.globalX(),
                    qevent.globalY(),
                    qevent.flags())
            elif qevent.type() == QtCore.QEvent.Wheel:
                qevent_str="{angleDelta={x=%s, y=%s}, phase=%s}" % (
                    qevent.angleDelta().x(),
                    qevent.angleDelta().y(),
                    qevent.phase())

            #
            # If the target QWidget is a scroll area's viewport,
            # pick up the parent
            #
            from PyQt5 import QtWidgets
            qwidget = uie.get_target_QWidget()
            if qwidget:
                parent = qwidget.parentWidget()
                if parent and isinstance(parent, QtWidgets.QAbstractScrollArea):
                    qwidget = parent

            parts.append("user_input_event={kind=%s, modifiers=0x%x, target={metaObject={className=%s}, windowTitle=%s}, source=%s, %s, source-as-qevent=%s}" % (
                kind_str,
                uie.modifiers,
                qwidget.metaObject().className(),
                qwidget.windowTitle(),
                uie.source,
                payload_str,
                qevent_str))
        print("### curpos: %s" % ", ".join(parts))
        return 0

curpos_details = curpos_details_t()
curpos_details.hook()
