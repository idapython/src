"""
summary: This file contains the CVT64 examples.

description:
  For more infortmation see SDK/plugins/cvt64_sample example
"""

import idaapi
import ida_idaapi
import ida_netnode

SAMPLE_NETNODE_NAME = "$ cvt64 py_sample netnode"
DEVICE_INDEX   = idaapi.BADADDR     # -1
IDPFLAGS_INDEX = idaapi.BADADDR     # -1
HASH_COMMENT   = "Comment"
HASH_ADDRESS   = "Address"

#--------------------------------------------------------------------------
class idp_listener_t(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def ev_cvt64_hashval(self, node, tag, name, data):
        helper = idaapi.netnode(SAMPLE_NETNODE_NAME)
        if helper == node and tag == ida_netnode.htag:
            if name == HASH_COMMENT:
                comment = helper.hashstr(name)
                helper.hashset_buf(name, comment)
                return 1
            if name == HASH_ADDRESS:
                address = helper.hashval_long(name)
                if address == ida_idaapi.BADADDR32: 
                    address = ida_idaapi.BADADDR
                    helper.hashset_idx(name, address)
                return 1
        return 0

    def ev_cvt64_supval(self, node, tag, idx, data):
        helper = idaapi.netnode(SAMPLE_NETNODE_NAME)
        if helper == node:
            if tag == ida_netnode.stag and idx == ida_idaapi.BADADDR32: 
                helper.supset(DEVICE_INDEX, data)
                return 1
            if tag == ida_netnode.atag and len(data):
                if idx == ida_idaapi.BADADDR32: 
                    idx = IDPFLAGS_INDEX
                val = int.from_bytes(data, 'little')
                if val == ida_idaapi.BADADDR32: 
                    val = ida_idaapi.BADADDR
                helper.altset(idx, val)
                return 1
        return 0

#--------------------------------------------------------------------------
# This class is instantiated once per each opened database.
class cvt64_ctx_t(idaapi.plugmod_t):

    def __init__(self):
        self.prochook = idp_listener_t()
        self.prochook.hook()

    def __del__(self):
        self.prochook.unhook()

    def run(self, arg):
        pass

#--------------------------------------------------------------------------
# This class is instantiated when IDA loads the plugin.
class cvt64_sample_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI | idaapi.PLUGIN_MOD
    comment = "IDAPython: An example how to implement CVT64 functionality"
    wanted_name = "IDAPython: CVT64 sample"
    wanted_hotkey = ""
    help = ""

    def init(self):
        return cvt64_ctx_t()

#--------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return cvt64_sample_t()
