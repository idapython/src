"""
summary: adding PyQt5 widgets into an `ida_kernwin.PluginForm`

description:
  Using `ida_kernwin.PluginForm.FormToPyQtWidget`, this script
  converts IDA's own dockable widget into a type that is
  recognized by PyQt5, which then enables populating it with
  regular Qt widgets.
"""

from PyQt5 import QtCore, QtGui, QtWidgets

class MyPluginFormClass(ida_kernwin.PluginForm):
    def OnCreate(self, form):
        """
        Called when the widget is created
        """

        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()


    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()

        layout.addWidget(
            QtWidgets.QLabel("Hello from <font color=red>PyQt</font>"))
        layout.addWidget(
            QtWidgets.QLabel("Hello from <font color=blue>IDAPython</font>"))

        self.parent.setLayout(layout)


    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        pass

plg = MyPluginFormClass()
plg.Show("PyQt hello world")
