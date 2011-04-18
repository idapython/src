# -----------------------------------------------------------------------
# This is an example illustrating how to:
# - enumerate imports
# - enumerate entrypoints
# - Use PluginForm class
# - Use PySide with PluginForm to create a Python UI
#
# (c) Hex-Rays
#
import idaapi
import idautils
from idaapi import PluginForm
from PySide import QtGui, QtCore

# --------------------------------------------------------------------------
class ImpExpForm_t(PluginForm):

    def imports_names_cb(self, ea, name, ord):
        self.items.append((ea, '' if not name else name, ord))
        # True -> Continue enumeration
        return True


    def BuildImports(self):
        tree = {}
        nimps = idaapi.get_import_module_qty()

        for i in xrange(0, nimps):
            name = idaapi.get_import_module_name(i)
            if not name:
                continue
            # Create a list for imported names
            self.items = []

            # Enum imported entries in this module
            idaapi.enum_import_names(i, self.imports_names_cb)

            if name not in tree:
                tree[name] = []
            tree[name].extend(self.items)

        return tree


    def BuildExports(self):
        return list(idautils.Entries())


    def PopulateTree(self):
        # Clear previous items
        self.tree.clear()

        # Build imports
        root = QtGui.QTreeWidgetItem(self.tree)
        root.setText(0, "Imports")

        for dll_name, imp_entries in self.BuildImports().items():
            imp_dll = QtGui.QTreeWidgetItem(root)
            imp_dll.setText(0, dll_name)

            for imp_ea, imp_name, imp_ord in imp_entries:
                item = QtGui.QTreeWidgetItem(imp_dll)
                item.setText(0, "%s [0x%08x]" %(imp_name, imp_ea))


        # Build exports
        root = QtGui.QTreeWidgetItem(self.tree)
        root.setText(0, "Exports")

        for exp_i, exp_ord, exp_ea, exp_name in self.BuildExports():
            item = QtGui.QTreeWidgetItem(root)
            item.setText(0, "%s [#%d] [0x%08x]" % (exp_name, exp_ord, exp_ea))


    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """

        # Get parent widget
        self.parent = self.FormToPySideWidget(form)

        # Create tree control
        self.tree = QtGui.QTreeWidget()
        self.tree.setHeaderLabels(("Names",))
        self.tree.setColumnWidth(0, 100)

        # Create layout
        layout = QtGui.QVBoxLayout()
        layout.addWidget(self.tree)

        self.PopulateTree()
        # Populate PluginForm
        self.parent.setLayout(layout)


    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        global ImpExpForm
        del ImpExpForm
        print "Closed"


    def Show(self):
        """Creates the form is not created or focuses it if it was"""
        return PluginForm.Show(self,
                               "Imports / Exports viewer",
                               options = PluginForm.FORM_PERSIST)

# --------------------------------------------------------------------------
def main():
    global ImpExpForm

    try:
        ImpExpForm
    except:
        ImpExpForm = ImpExpForm_t()

    ImpExpForm.Show()

# --------------------------------------------------------------------------
main()