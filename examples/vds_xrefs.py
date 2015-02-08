""" Xref plugin for Hexrays Decompiler

Author: EiNSTeiN_ <einstein@g3nius.org>

Show decompiler-style Xref when the X key is pressed in the Decompiler window.

- It supports any global name: functions, strings, integers, etc.
- It supports structure member.

"""

import idautils
import idaapi
import idc

import traceback

try:
    from PyQt4 import QtCore, QtGui
    print 'Using PyQt'
except:
    print 'PyQt not available'

    try:
        from PySide import QtGui, QtCore
        print 'Using PySide'
    except:
        print 'PySide not available'

XREF_EA = 0
XREF_STRUC_MEMBER = 1

class XrefsForm(idaapi.PluginForm):

    def __init__(self, target):

        idaapi.PluginForm.__init__(self)

        self.target = target

        if type(self.target) == idaapi.cfunc_t:

            self.__type = XREF_EA
            self.__ea = self.target.entry_ea
            self.__name = 'Xrefs of %x' % (self.__ea, )

        elif type(self.target) == idaapi.cexpr_t and self.target.opname == 'obj':

            self.__type = XREF_EA
            self.__ea = self.target.obj_ea
            self.__name = 'Xrefs of %x' % (self.__ea, )

        elif type(self.target) == idaapi.cexpr_t and self.target.opname in ('memptr', 'memref'):

            self.__type = XREF_STRUC_MEMBER
            name = self.get_struc_name()
            self.__name = 'Xrefs of %s' % (name, )

        else:
            raise ValueError('cannot show xrefs for this kind of target')

        return

    def get_struc_name(self):

        x = self.target.operands['x']
        m = self.target.operands['m']

        xtype = x.type
        xtype.remove_ptr_or_array()
        typename = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, xtype, '', '')

        sid = idc.GetStrucIdByName(typename)
        member = idc.GetMemberName(sid, m)

        return '%s::%s' % (typename, member)

    def OnCreate(self, form):

        # Get parent widget
        try:
            self.parent = self.FormToPySideWidget(form)
        except:
            self.parent = self.FormToPyQtWidget(form)

        self.populate_form()

        return

    def Show(self):
        idaapi.PluginForm.Show(self, self.__name)
        return

    def populate_form(self):
        # Create layout
        layout = QtGui.QVBoxLayout()

        layout.addWidget(QtGui.QLabel(self.__name))
        self.table = QtGui.QTableWidget()
        layout.addWidget(self.table)

        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderItem(0, QtGui.QTableWidgetItem("Address"))
        self.table.setHorizontalHeaderItem(1, QtGui.QTableWidgetItem("Function"))
        self.table.setHorizontalHeaderItem(2, QtGui.QTableWidgetItem("Line"))

        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(2, 450)

        self.table.cellDoubleClicked.connect(self.double_clicked)

        #~ self.table.setSelectionMode(QtGui.QAbstractItemView.NoSelection)
        self.table.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows )
        self.parent.setLayout(layout)

        self.populate_table()

        return

    def double_clicked(self, row, column):

        ea = self.functions[row]
        idaapi.open_pseudocode(ea, True)

        return

    def get_decompiled_line(self, cfunc, ea):

        print repr(ea)
        if ea not in cfunc.eamap:
            print 'strange, %x is not in %x eamap' % (ea, cfunc.entry_ea)
            return

        insnvec = cfunc.eamap[ea]

        lines = []
        for stmt in insnvec:

            qp = idaapi.qstring_printer_t(cfunc.__deref__(), False)

            stmt._print(0, qp)
            s = qp.s.split('\n')[0]

            #~ s = idaapi.tag_remove(s)
            lines.append(s)

        return '\n'.join(lines)

    def get_items_for_ea(self, ea):

        frm = [x.frm for x in idautils.XrefsTo(self.__ea)]

        items = []
        for ea in frm:
            try:
                cfunc = idaapi.decompile(ea)

                self.functions.append(cfunc.entry_ea)
                self.items.append((ea, idc.GetFunctionName(cfunc.entry_ea), self.get_decompiled_line(cfunc, ea)))

            except Exception as e:
                print 'could not decompile: %s' % (str(e), )
                raise

        return

    def get_items_for_type(self):

        x = self.target.operands['x']
        m = self.target.operands['m']

        xtype = x.type
        xtype.remove_ptr_or_array()
        typename = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, xtype, '', '')

        addresses = []
        for ea in idautils.Functions():

            try:
                cfunc = idaapi.decompile(ea)
            except:
                print 'Decompilation of %x failed' % (ea, )
                continue

            str(cfunc)

            for citem in cfunc.treeitems:
                citem = citem.to_specific_type
                if not (type(citem) == idaapi.cexpr_t and citem.opname in ('memptr', 'memref')):
                    continue

                _x = citem.operands['x']
                _m = citem.operands['m']
                _xtype = _x.type
                _xtype.remove_ptr_or_array()
                _typename = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, _xtype, '', '')

                #~ print 'in', hex(cfunc.entry_ea), _typename, _m

                if not (_typename == typename and _m == m):
                    continue

                parent = citem
                while parent:
                    if type(parent.to_specific_type) == idaapi.cinsn_t:
                        break
                    parent = cfunc.body.find_parent_of(parent)

                if not parent:
                    print 'cannot find parent statement (?!)'
                    continue

                if parent.ea in addresses:
                    continue

                if parent.ea == idaapi.BADADDR:
                    print 'parent.ea is BADADDR'
                    continue

                addresses.append(parent.ea)

                self.functions.append(cfunc.entry_ea)
                self.items.append((
                        parent.ea,
                        idc.GetFunctionName(cfunc.entry_ea),
                        self.get_decompiled_line(cfunc, parent.ea)))


        return []

    def populate_table(self):

        self.functions = []
        self.items = []

        if self.__type == XREF_EA:
            self.get_items_for_ea(self.__ea)
        else:
            self.get_items_for_type()

        self.table.setRowCount(len(self.items))

        i = 0
        for item in self.items:
            address, func, line = item
            item = QtGui.QTableWidgetItem('0x%x' % (address, ))
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(i, 0, item)
            item = QtGui.QTableWidgetItem(func)
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(i, 1, item)
            item = QtGui.QTableWidgetItem(line)
            item.setFlags(item.flags() ^ QtCore.Qt.ItemIsEditable)
            self.table.setItem(i, 2, item)

            i += 1

        self.table.resizeRowsToContents()

        return

    def OnClose(self, form):
        pass


class show_xrefs_ah_t(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.sel = None

    def activate(self, ctx):
        vu = idaapi.get_tform_vdui(ctx.form)
        if not vu or not self.sel:
            print "No vdui? Strange, since this action should be enabled only for pseudocode views."
            return 0

        form = XrefsForm(self.sel)
        form.Show()
        return 1

    def update(self, ctx):
        vu = idaapi.get_tform_vdui(ctx.form)
        if not vu:
            return idaapi.AST_DISABLE_FOR_FORM
        else:
            vu.get_current_item(idaapi.USE_KEYBOARD)
            item = vu.item
            self.sel = None
            if item.citype == idaapi.VDI_EXPR and item.it.to_specific_type.opname in ('obj', 'memref', 'memptr'):
                # if an expression is selected. verify that it's either a cot_obj, cot_memref or cot_memptr
                self.sel = item.it.to_specific_type

            elif item.citype == idaapi.VDI_FUNC:
                # if the function itself is selected, show xrefs to it.
                self.sel = item.f

            return idaapi.AST_ENABLE if self.sel else idaapi.AST_DISABLE

class hexrays_callback_info(object):

    def __init__(self):
        return

    def event_callback(self, event, *args):

        try:
            if event == idaapi.hxe_populating_popup:
                form, phandle, vu = args
                idaapi.attach_action_to_popup(form, phandle, "vdsxrefs:show", None)
        except:
            traceback.print_exc()

        return 0

if idaapi.init_hexrays_plugin():
    adesc = idaapi.action_desc_t('vdsxrefs:show', 'Show xrefs', show_xrefs_ah_t(), "Ctrl+X")
    if idaapi.register_action(adesc):
        i = hexrays_callback_info()
        idaapi.install_hexrays_callback(i.event_callback)
    else:
        print "Couldn't register action."
else:
    print 'hexrays is not available.'
