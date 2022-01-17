"""
summary: injecting commands in the "Output" window

description:
  This example illustrates how one can execute commands in the
  "Output" window, from their own widgets.

  A few notes:

  * the original, underlying `cli:Execute` action, that has to be
    triggered for the code present in the input field to execute
    and be placed in the history, requires that the input field
    has focus (otherwise it simply won't do anything.)
  * this, in turn, forces us to do "delayed" execution of that action,
    hence the need for a `QTimer`
  * the IDA/SWiG 'TWidget' type that we retrieve through
    `ida_kernwin.find_widget`, is not the same type as a
    `QtWidgets.QWidget`. We therefore need to convert it using
    `ida_kernwin.PluginForm.TWidgetToPyQtWidget`
"""

from PyQt5 import QtCore
from PyQt5 import QtGui
from PyQt5 import QtWidgets

import ida_kernwin
import ida_segment

import idc

delayed_exec_timer = QtCore.QTimer()

def show_dialog():
    dialog = QtWidgets.QDialog()
    dialog.setWindowTitle("Inject command")
    dialog.setMinimumSize(600, 480)

    run_text = "Run"
    buttons_box = QtWidgets.QDialogButtonBox()
    button = buttons_box.addButton(run_text, QtWidgets.QDialogButtonBox.AcceptRole)
    button.setDefault(True)
    button.clicked.connect(dialog.accept)

    text_edit = QtWidgets.QPlainTextEdit()
    text_edit.setPlaceholderText(
        "Type an expression, and press '%s' to execute through the regular input" % run_text)

    layout = QtWidgets.QVBoxLayout()
    layout.addWidget(text_edit)
    layout.addWidget(buttons_box)

    dialog.setLayout(layout)

    # disable script timeout, otherwise a "Please wait ..." dialog
    # might briefly show after the dialog was accepted/rejected
    with ida_kernwin.disabled_script_timeout_t():
        if dialog.exec_() == QtWidgets.QDialog.Accepted:

            # We'll now have to schedule a call to the standard
            # 'execute' action. We can't call it right away, because
            # the "Output" window doesn't have focus, and thus
            # the action will fail to execute since it requires
            # the "Output" window as context.
            text = text_edit.toPlainText()

            def delayed_exec(*args):
                output_window_title = "Output"
                tw = ida_kernwin.find_widget(output_window_title)
                if not tw:
                    raise Exception("Couldn't find widget '%s'" % output_window_title)

                # convert from a SWiG 'TWidget*' facade,
                # into an object that PyQt will understand
                w = ida_kernwin.PluginForm.TWidgetToPyQtWidget(tw)

                line_edit = w.findChild(QtWidgets.QLineEdit)
                if not line_edit:
                    raise Exception("Couldn't find input")
                line_edit.setFocus() # ensure it has focus
                QtWidgets.QApplication.instance().processEvents() # and that it received the focus event

                # inject text into widget
                line_edit.setText(text)

                # and execute the standard 'execute' action
                ida_kernwin.process_ui_action("cli:Execute")

            delayed_exec_timer.singleShot(0, delayed_exec)


show_dialog()
