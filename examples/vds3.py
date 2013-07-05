""" Invert the then and else blocks of a cif_t.

Author: EiNSTeiN_ <einstein@g3nius.org>

This is a rewrite in Python of the vds3 example that comes with hexrays sdk.


The main difference with the original C code is that when we create the inverted 
condition object, the newly created cexpr_t instance is given to the hexrays and 
must not be freed by swig. To achieve this, we have to change the 'thisown' flag 
when appropriate. See http://www.swig.org/Doc1.3/Python.html#Python_nn35

"""

import idautils
import idaapi
import idc

import traceback

NETNODE_NAME = '$ hexrays-inverted-if'

class hexrays_callback_info(object):
    
    def __init__(self):
        self.vu = None
        
        self.node = idaapi.netnode()
        if not self.node.create(NETNODE_NAME):
            # node exists
            self.load()
        else:
            self.stored = []
        
        return
    
    def load(self):
        
        self.stored = []
        
        try:
            data = self.node.getblob(0, 'I')
            if data:
                self.stored = eval(data)
                print 'Invert-if: Loaded %s' % (repr(self.stored), )
        except:
            print 'Failed to load invert-if locations'
            traceback.print_exc()
            return
        
        return
    
    def save(self):
        
        try:
            self.node.setblob(repr(self.stored), 0, 'I')
        except:
            print 'Failed to save invert-if locations'
            traceback.print_exc()
            return
        
        return
    
    def invert_if(self, cfunc, insn):
        
        if insn.opname != 'if':
            return False
        
        cif = insn.details
        
        if not cif.ithen or not cif.ielse:
            return False
        
        idaapi.qswap(cif.ithen, cif.ielse)
        cond = idaapi.cexpr_t(cif.expr)
        notcond = idaapi.lnot(cond)
        cond.thisown = 0 # the new wrapper 'notcond' now holds the reference to the cexpr_t
        
        cif.expr.swap(notcond)
        
        return True
    
    def add_location(self, ea):
        if ea in self.stored:
            self.stored.remove(ea)
        else:
            self.stored.append(ea)
        self.save()
        return
    
    def invert_if_event(self, vu):
        
        vu.get_current_item(idaapi.USE_KEYBOARD)
        item = vu.item
        
        cfunc = vu.cfunc.__deref__()
        
        if item.citype != idaapi.VDI_EXPR:
            return False
        
        if self.invert_if(cfunc, item.it.to_specific_type):
            vu.refresh_ctext()
            
            self.add_location(item.it.ea)
        
        return True
    
    def restore(self, cfunc):
        
        #~ print 'restoring invert-if for %x' % (cfunc.entry_ea, )
        
        str(cfunc) # generate treeitems.
        
        restored = False
        
        for item in cfunc.treeitems:
            item = item.to_specific_type
            if item.opname == 'if' and item.ea in self.stored:
                if self.invert_if(cfunc, item):
                    restored = True
                    #~ print 'restore invert-if location %x' % (item.ea, )
                else:
                    print 'invert-if location %x: NOT RESTORED' % (item.ea, )
        
        return restored
    
    def menu_callback(self):
        try:
            self.invert_if_event(self.vu)
        except:
            traceback.print_exc()
        return 0
    
    def event_callback(self, event, *args):
        
        try:
            if event == idaapi.hxe_keyboard:
                vu, keycode, shift = args
                
                if idaapi.lookup_key_code(keycode, shift, True) == idaapi.get_key_code("I") and shift == 0:
                    if self.invert_if_event(vu):
                        return 1
                
            elif event == idaapi.hxe_right_click:
                self.vu = args[0]
                idaapi.add_custom_viewer_popup_item(self.vu.ct, "Invert then/else", "I", self.menu_callback)
            
            elif event == idaapi.hxe_maturity:
                cfunc, maturity = args
                
                if maturity == idaapi.CMAT_FINAL:
                    self.restore(cfunc)
        except:
            traceback.print_exc()
        
        return 0

if idaapi.init_hexrays_plugin():
    i = hexrays_callback_info()
    idaapi.install_hexrays_callback(i.event_callback)
else:
    print 'invert-if: hexrays is not available.'
