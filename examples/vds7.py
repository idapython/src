""" It demonstrates how to iterate a cblock_t object.

Author: EiNSTeiN_ <einstein@g3nius.org>

This is a rewrite in Python of the vds7 example that comes with hexrays sdk.
"""

import idautils
import idaapi
import idc

import traceback

class cblock_visitor_t(idaapi.ctree_visitor_t):

    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        return
    
    def visit_insn(self, ins):
        
        try:
            if ins.op == idaapi.cit_block:
                self.dump_block(ins.ea, ins.cblock)
        except:
            traceback.print_exc()
        
        return 0
    
    def dump_block(self, ea, b):
        # iterate over all block instructions
        print "dumping block %x" % (ea, )
        for ins in b:
            print "  %x: insn %s" % (ins.ea, ins.opname)
        
        return

class hexrays_callback_info(object):
    
    def __init__(self):
        return
    
    def event_callback(self, event, *args):
        
        try:
            if event == idaapi.hxe_maturity:
                cfunc, maturity = args
                
                if maturity == idaapi.CMAT_BUILT:
                    cbv = cblock_visitor_t()
                    cbv.apply_to(cfunc.body, None)
            
        except:
            traceback.print_exc()
        
        return 0

if idaapi.init_hexrays_plugin():
    i = hexrays_callback_info()
    idaapi.install_hexrays_callback(i.event_callback)
else:
    print 'cblock visitor: hexrays is not available.'
