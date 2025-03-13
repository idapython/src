"""
summary: Add missing inodes in dirtree structure in "/lost+found" directory

description:
  How to collects inodes for various dirtrees ('Local Types', 'Names',
  'Functions', 'Imports', 'Address bookmark' and 'Breakpoints') in both
  the dirtree structure and the database.
  Create a directory an links inodes to them in the dirtree structure
  You cannot add all inodes to the "/lost+found" directory because inodes
  can be at various places in a dirtree structure.
  The early dirtree implementations were not perfect and may have missed to
  add some inodes in the tree structure, this script corrects this issue.

keywords: dirtree, recovery
"""

import ida_dirtree
from ida_dirtree import dirtree_t
import ida_typeinf
import ida_funcs
import ida_name
import ida_dbg
import ida_nalt
import ida_kernwin
import ida_moves


def get_ltypes_inode(n):
    inode = n + 1
    name = ida_typeinf.get_numbered_type_name(None, inode)
    if name is None:
        # if the name is None, we have a #deleted type,
        # present in flat mode but not in fulltree mode
        return True, None
    else:
        return False, inode


def get_func_inode(n):
    inode = ida_funcs.getn_func(n).start_ea
    return False, inode


def get_name_inode(n):
    inode = ida_name.get_nlist_ea(n)
    if inode is None:
        print(hex(inode))
    return False, inode


list_inodes_in_idb = []
def get_import_list():
    def imp_cb(ea, name, ordinal):
        list_inodes_in_idb.append(ea)
        return True
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        ida_nalt.enum_import_names(i, imp_cb)
    list_inodes_in_idb.sort()
    return len(list_inodes_in_idb)


def get_nth_inode_in_idb(n):
    return False, list_inodes_in_idb[n]


def get_idaplace_list_inodes_in_idb():
    id = ida_kernwin.get_place_class_id("idaplace_t")
    p = ida_kernwin.get_place_class_template(id)
    r = ida_moves.renderer_info_t()
    l = ida_moves.lochist_entry_t(p, r)
    for idx in range(ida_moves.bookmarks_t.size(l, None)):
        ida_moves.bookmarks_t.get(l, idx, None)
        idaloc = ida_kernwin.place_t.as_idaplace_t(l.place())
        list_inodes_in_idb.append(idaloc.ea)
    list_inodes_in_idb.sort()
    return len(list_inodes_in_idb)


def get_bpt_inode(n):
    bpt = ida_dbg.bpt_t()
    if not ida_dbg.getn_bpt(n, bpt):
        return True, None
    return False, bpt.bptid


class dt_collect_inode_t(ida_dirtree.dirtree_visitor_t):
    def __init__(self):
        ida_dirtree.dirtree_visitor_t.__init__(self)
        self.list_inodes_in_dirtree = []
    def visit(self, c, de):
        if dirtree_t.isfile(de):
            self.list_inodes_in_dirtree.append(de.idx)
        return 0


std_recovery_data = [
        ( ida_dirtree.DIRTREE_LOCAL_TYPES, ida_typeinf.get_ordinal_count, get_ltypes_inode, "Local Types" ),
        ( ida_dirtree.DIRTREE_FUNCS, ida_funcs.get_func_qty, get_func_inode, "Local Types" ),
        ( ida_dirtree.DIRTREE_NAMES, ida_name.get_nlist_size, get_name_inode, "Names" ),
        ( ida_dirtree.DIRTREE_IMPORTS, get_import_list, get_nth_inode_in_idb, "Imports" ),
        ( ida_dirtree.DIRTREE_IDAPLACE_BOOKMARKS, get_idaplace_list_inodes_in_idb, get_nth_inode_in_idb, "Address bookmarks" ),
        ( ida_dirtree.DIRTREE_BPTS, ida_dbg.get_bpt_qty, get_bpt_inode, "Breakpoints" ),
    ]


for dt_id, get_count_and_maybe_list_inodes_in_idb, get_inode, title in std_recovery_data:
    dt = ida_dirtree.get_std_dirtree(dt_id)
    print("### Dirtree ", title)
    list_inodes_in_idb = []
    collector = dt_collect_inode_t()
    dt.traverse(collector)
    set_inodes_in_dirtree = set(collector.list_inodes_in_dirtree)
    nb_inodes = get_count_and_maybe_list_inodes_in_idb()
    nb_not_list = 0
    nb_list = len(set_inodes_in_dirtree)
    print("Number of unique inodes in the idb: %d\nNumber of unique inodes in fulltree mode: %d"%(nb_inodes, nb_list))

    if nb_list < nb_inodes:
        err = dt.mkdir("/lost+found")
        if err != ida_dirtree.DTE_OK:
            print(dt.errstr(err))
        err = dt.chdir("/lost+found")
        if err != ida_dirtree.DTE_OK:
            print(dt.errstr(err))
        for n in range(nb_inodes):
            inc, inode = get_inode(n)
            if inode is not None:
                if inode not in set_inodes_in_dirtree:
                    err = dt.link(inode)
                    if err != ida_dirtree.DTE_OK:
                        print("Failed to link inode ", hex(inode), " ", dt.errstr(err) )
                    inc = True
            if inc:
                nb_not_list += 1
            if nb_inodes == nb_list + nb_not_list:
                break

