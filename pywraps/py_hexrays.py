# -----------------------------------------------------------------------
#<pycode(py_hexrays)>
import ida_funcs
import ida_idaapi

hexrays_failure_t.__str__ = lambda self: str("%x: %s" % (self.errea, self.desc()))

# ---------------------------------------------------------------------
# Renamings
is_allowed_on_small_struni = accepts_small_udts
is_small_struni = is_small_udt
mbl_array_t = mba_t

# NOTE: Strictly for backward-compatibily reasons (i.e., not
# to break existing scripts), and will never be thrown.
class DecompilationFailure(Exception):
    pass

# NOTE: We need to keep this `decompile` prototype because some
# scripts might be passing arguments by keyword
def decompile(ea, hf=None, flags=0):
    """
    Decompile a function.

    @param ea an address belonging to the function, or an ida_funcs.func_t object
    @param hf extended error information (if failed)
    @param flags decomp_flags bitwise combination of `DECOMP_...` bits
    @return the decompilation result (a `ida_hexrays.cfunc_t` wrapper), or None
    """
    return decompile_func(ea, hf, flags)

# ---------------------------------------------------------------------
# listify all list types
import ida_idaapi
ida_idaapi._listify_types(
        cinsnptrvec_t,
        ctree_items_t,
        qvector_lvar_t,
        qvector_carg_t,
        qvector_ccase_t,
        hexwarns_t,
        history_t,
        lvar_saved_infos_t,
        ui_stroff_ops_t)

def citem_to_specific_type(self):
    """ cast the citem_t object to its more specific type, either cexpr_t or cinsn_t. """

    if self.op >= cot_empty and self.op <= cot_last:
        return self.cexpr
    elif self.op >= cit_empty and self.op < cit_end:
        return self.cinsn

    raise RuntimeError('unknown op type %s' % (repr(self.op), ))
citem_t.to_specific_type = property(citem_to_specific_type)

""" array used for translating cinsn_t->op type to their names. """
cinsn_t.op_to_typename = {}
for k in dir(_ida_hexrays):
    if k.startswith('cit_'):
        cinsn_t.op_to_typename[getattr(_ida_hexrays, k)] = k[4:]

""" array used for translating cexpr_t->op type to their names. """
cexpr_t.op_to_typename = {}
for k in dir(_ida_hexrays):
    if k.startswith('cot_'):
        cexpr_t.op_to_typename[getattr(_ida_hexrays, k)] = k[4:]

def property_op_to_typename(self):
    return self.op_to_typename[self.op]
cinsn_t.opname = property(property_op_to_typename)
cexpr_t.opname = property(property_op_to_typename)

def cexpr_operands(self):
    """ return a dictionary with the operands of a cexpr_t. """

    if self.op >= cot_comma and self.op <= cot_asgumod or \
        self.op >= cot_lor and self.op <= cot_fdiv or \
        self.op == cot_idx:
        return {'x': self.x, 'y': self.y}

    elif self.op == cot_tern:
        return {'x': self.x, 'y': self.y, 'z': self.z}

    elif self.op in [cot_fneg, cot_neg, cot_sizeof] or \
        self.op >= cot_lnot and self.op <= cot_predec:
        return {'x': self.x}

    elif self.op == cot_cast:
        return {'type': self.type, 'x': self.x}

    elif self.op == cot_call:
        return {'x': self.x, 'a': self.a}

    elif self.op in [cot_memref, cot_memptr]:
        return {'x': self.x, 'm': self.m}

    elif self.op == cot_num:
        return {'n': self.n}

    elif self.op == cot_fnum:
        return {'fpc': self.fpc}

    elif self.op == cot_str:
        return {'string': self.string}

    elif self.op == cot_obj:
        return {'obj_ea': self.obj_ea}

    elif self.op == cot_var:
        return {'v': self.v}

    elif self.op == cot_helper:
        return {'helper': self.helper}

    raise RuntimeError('unknown op type %s' % self.opname)
cexpr_t.operands = property(cexpr_operands)

def cinsn_details(self):
    """
    return the details pointer for the cinsn_t object depending on the value of its op member. \
    this is one of the cblock_t, cif_t, etc. objects.
    """

    if self.op not in self.op_to_typename:
        raise RuntimeError('unknown item->op type')

    opname = self.opname
    if opname == 'empty':
        return self

    if opname in ['break', 'continue']:
        return None

    return getattr(self, 'c' + opname)
cinsn_t.details = property(cinsn_details)

cfuncptr_t.__str__ = lambda self: str(self.__deref__())
cfuncptr_t.__eq__ = lambda self, other: self.__ptrval__() == other.__ptrval__() if isinstance(other, cfuncptr_t) else False

import ida_typeinf
def cfunc_type(self):
    """ Get the function's return type tinfo_t object. """
    tif = ida_typeinf.tinfo_t()
    result = self.get_func_type(tif)
    if not result:
        return
    return tif
cfunc_t.type = property(cfunc_type)
cfuncptr_t.type = property(lambda self: self.__deref__().type)

cfunc_t.arguments = property(lambda self: [self.lvars[i] for i in self.argidx])
cfuncptr_t.arguments = property(lambda self: self.__deref__().arguments)

cfunc_t.lvars = property(cfunc_t.get_lvars)
cfuncptr_t.lvars = property(lambda self: self.__deref__().lvars)
cfunc_t.warnings = property(cfunc_t.get_warnings)
cfuncptr_t.warnings = property(lambda self: self.__deref__().warnings)
cfunc_t.pseudocode = property(cfunc_t.get_pseudocode)
cfuncptr_t.pseudocode = property(lambda self: self.__deref__().get_pseudocode())
cfunc_t.eamap = property(cfunc_t.get_eamap)
cfuncptr_t.eamap = property(lambda self: self.__deref__().get_eamap())
cfunc_t.boundaries = property(cfunc_t.get_boundaries)
cfuncptr_t.boundaries = property(lambda self: self.__deref__().get_boundaries())

#pragma SWIG nowarn=+503

lvar_t.used = property(lvar_t.used)
lvar_t.typed = property(lvar_t.typed)
lvar_t.mreg_done = property(lvar_t.mreg_done)
lvar_t.has_nice_name = property(lvar_t.has_nice_name)
lvar_t.is_unknown_width = property(lvar_t.is_unknown_width)
lvar_t.has_user_info = property(lvar_t.has_user_info)
lvar_t.has_user_name = property(lvar_t.has_user_name)
lvar_t.has_user_type = property(lvar_t.has_user_type)
lvar_t.is_result_var = property(lvar_t.is_result_var)
lvar_t.is_arg_var = property(lvar_t.is_arg_var)
lvar_t.is_fake_var = property(lvar_t.is_fake_var)
lvar_t.is_overlapped_var = property(lvar_t.is_overlapped_var)
lvar_t.is_floating_var = property(lvar_t.is_floating_var)
lvar_t.is_spoiled_var = property(lvar_t.is_spoiled_var)
lvar_t.is_mapdst_var = property(lvar_t.is_mapdst_var)

# dictify all dict-like types
def _map_as_dict(maptype, name, keytype, valuetype):

    maptype.keytype = keytype
    maptype.valuetype = valuetype

    for fctname in ['begin', 'end', 'first', 'second', 'next', \
                        'find', 'insert', 'erase', 'clear', 'size']:
        fct = getattr(_ida_hexrays, name + '_' + fctname)
        setattr(maptype, '__' + fctname, fct)

    maptype.__len__ = maptype.size
    maptype.__getitem__ = maptype.at

    maptype.begin = lambda self, *args: self.__begin(self, *args)
    maptype.end = lambda self, *args: self.__end(self, *args)
    maptype.first = lambda self, *args: self.__first(*args)
    maptype.second = lambda self, *args: self.__second(*args)
    maptype.next = lambda self, *args: self.__next(*args)
    maptype.find = lambda self, *args: self.__find(self, *args)
    maptype.insert = lambda self, *args: self.__insert(self, *args)
    maptype.erase = lambda self, *args: self.__erase(self, *args)
    maptype.clear = lambda self, *args: self.__clear(self, *args)
    maptype.size = lambda self, *args: self.__size(self, *args)

    def _map___iter__(self):
        """ Iterate over dictionary keys. """
        return self.iterkeys()
    maptype.__iter__ = _map___iter__

    def _map___getitem__(self, key):
        """ Returns the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of key should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        return self.second(self.find(key))
    maptype.__getitem__ = _map___getitem__

    def _map___setitem__(self, key, value):
        """ Returns the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if not isinstance(value, self.valuetype):
            raise KeyError('type of `value` should be ' + repr(self.valuetype) + ' but got ' + type(value))
        self.insert(key, value)
        return
    maptype.__setitem__ = _map___setitem__

    def _map___delitem__(self, key):
        """ Removes the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        self.erase(self.find(key))
        return
    maptype.__delitem__ = _map___delitem__

    def _map___contains__(self, key):
        """ Returns true if the specified key exists in the . """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if self.find(key) != self.end():
            return True
        return False
    maptype.__contains__ = _map___contains__

    def _map_clear(self):
        self.clear()
        return
    maptype.clear = _map_clear

    def _map_copy(self):
        ret = {}
        for k in self.iterkeys():
            ret[k] = self[k]
        return ret
    maptype.copy = _map_copy

    def _map_get(self, key, default=None):
        if key in self:
            return self[key]
        return default
    maptype.get = _map_get

    def _map_iterkeys(self):
        iter = self.begin()
        while iter != self.end():
            yield self.first(iter)
            iter = self.next(iter)
        return
    maptype.iterkeys = _map_iterkeys

    def _map_itervalues(self):
        iter = self.begin()
        while iter != self.end():
            yield self.second(iter)
            iter = self.next(iter)
        return
    maptype.itervalues = _map_itervalues

    def _map_iteritems(self):
        iter = self.begin()
        while iter != self.end():
            yield (self.first(iter), self.second(iter))
            iter = self.next(iter)
        return
    maptype.iteritems = _map_iteritems

    def _map_keys(self):
        return list(self.iterkeys())
    maptype.keys = _map_keys

    def _map_values(self):
        return list(self.itervalues())
    maptype.values = _map_values

    def _map_items(self):
        return list(self.iteritems())
    maptype.items = _map_items

    def _map_has_key(self, key):
        return key in self
    maptype.has_key = _map_has_key

    def _map_pop(self, key):
        """ Sets the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key not in self:
            raise KeyError('key not found')
        ret = self[key]
        del self[key]
        return ret
    maptype.pop = _map_pop

    def _map_popitem(self):
        """ Sets the value associated with the provided key. """
        if len(self) == 0:
            raise KeyError('key not found')
        key = self.keys()[0]
        return (key, self.pop(key))
    maptype.popitem = _map_popitem

    def _map_setdefault(self, key, default=None):
        """ Sets the value associated with the provided key. """
        if not isinstance(key, self.keytype):
            raise KeyError('type of `key` should be ' + repr(self.keytype) + ' but got ' + repr(type(key)))
        if key in self:
            return self[key]
        self[key] = default
        return default
    maptype.setdefault = _map_setdefault

_map_as_dict(user_cmts_t, 'user_cmts', treeloc_t, citem_cmt_t)
_map_as_dict(user_numforms_t, 'user_numforms', operand_locator_t, number_format_t)
_map_as_dict(user_iflags_t, 'user_iflags', citem_locator_t, int)
import ida_pro
_map_as_dict(user_unions_t, 'user_unions', ida_idaapi.integer_types, ida_pro.intvec_t)
_map_as_dict(eamap_t, 'eamap', ida_idaapi.long_type, cinsnptrvec_t)
import ida_range
_map_as_dict(boundaries_t, 'boundaries', cinsn_t, ida_range.rangeset_t)

#
# Object ownership
#
def _call_with_transferrable_ownership(fun, *args):
    e = args[0]
    was_owned = e.thisown
    res = fun(e, *args[1:])
    # ATM, 'res' doesn't own the resulting cexpr_t.
    # In case 'fun'
    #   - created a new object: we want to own that one in case 'e' was owned
    #   - didn't create a new object: we will remove & re-gain ownership on
    #                                 the same underlying cexpr_t. No biggie.
    if was_owned:
        if res:
            e._maybe_disown_and_deregister()
            res._own_and_register()
    else:
        debug_hexrays_ctree("NOTE: call_with_transferrable_ownership() called with non-IDAPython-owned object. Is this intentional?")
    return res

def lnot(e):
    return _call_with_transferrable_ownership(_ll_lnot, e)

def make_ref(e):
    return _call_with_transferrable_ownership(_ll_make_ref, e)

def dereference(e, ptrsize, is_float=False):
    return _call_with_transferrable_ownership(_ll_dereference, e, ptrsize, is_float)

def call_helper(rettype, args, *rest):
    res = _ll_call_helper(rettype, args, *rest)
    if res:
        res._own_and_register()
        if type(args) == carglist_t:
            args.thisown = False
    return res

def new_block():
    res = _ll_new_block()
    if res:
        res._own_and_register()
    return res

def make_num(*args):
    res = _ll_make_num(*args)
    if res:
        res._own_and_register()
    return res

def create_helper(*args):
    res = _ll_create_helper(*args)
    if res:
        res._own_and_register()
    return res

# ----------------

class __cbhooks_t(Hexrays_Hooks):

    instances = []

    def __init__(self, callback):
        self.callback = callback
        self.instances.append(self)
        Hexrays_Hooks.__init__(self)

    def maturity(self, *args): return self.callback(hxe_maturity, *args)
    def interr(self, *args): return self.callback(hxe_interr, *args)
    def print_func(self, *args): return self.callback(hxe_print_func, *args)
    def func_printed(self, *args): return self.callback(hxe_func_printed, *args)
    def open_pseudocode(self, *args): return self.callback(hxe_open_pseudocode, *args)
    def switch_pseudocode(self, *args): return self.callback(hxe_switch_pseudocode, *args)
    def refresh_pseudocode(self, *args): return self.callback(hxe_refresh_pseudocode, *args)
    def close_pseudocode(self, *args): return self.callback(hxe_close_pseudocode, *args)
    def keyboard(self, *args): return self.callback(hxe_keyboard, *args)
    def right_click(self, *args): return self.callback(hxe_right_click, *args)
    def double_click(self, *args): return self.callback(hxe_double_click, *args)
    def curpos(self, *args): return self.callback(hxe_curpos, *args)
    def create_hint(self, *args): return self.callback(hxe_create_hint, *args)
    def text_ready(self, *args): return self.callback(hxe_text_ready, *args)
    def populating_popup(self, *args): return self.callback(hxe_populating_popup, *args)
    # NOTE: Do not add support for new notifications here;
    # non-Hexrays_Hooks callbacks are deprecated.

def install_hexrays_callback(callback):
    "Deprecated. Please use Hexrays_Hooks instead"
    h = __cbhooks_t(callback)
    h.hook()
    return True

def remove_hexrays_callback(callback):
    "Deprecated. Please use Hexrays_Hooks instead"
    for inst in __cbhooks_t.instances:
        if inst.callback == callback:
            inst.unhook()
            __cbhooks_t.instances.remove(inst)
            return 1
    return 0

#</pycode(py_hexrays)>
