"""
summary: A widget that can show tabular data either as a simple table,
  or with a tree-like structure.

description:
  By adding the necessary bits to a ida_kernwin.Choose subclass,
  IDA can show the otherwise tabular data, in a tree-like fashion.

  The important bits to enable this are:

    * ida_dirtree.dirspec_t (and my_dirspec_t)
    * ida_kernwin.CH_HAS_DIRTREE
    * ida_kernwin.Choose.OnGetDirTree
    * ida_kernwin.Choose.OnIndexToInode

keywords: chooser, folders, actions

see_also: choose, choose_multi
"""

import inspect

import ida_kernwin
import ida_dirtree
import ida_netnode

class my_dirspec_t(ida_dirtree.dirspec_t):

    def __init__(self, chooser):
        ida_dirtree.dirspec_t.__init__(self)
        self.chooser = chooser

    def log_frame(self):
        if self.chooser.dirspec_log:
            stack = inspect.stack()
            frame, _, _, _, _, _ = stack[1]
            args, _, _, values = inspect.getargvalues(frame)
            print(">>> %s: args=%s" % (inspect.getframeinfo(frame)[2], [(i, values[i]) for i in args[1:]]))

    def get_name(self, inode, flags):
        self.log_frame()
        def find_inode(index, ordinal, _inode):
            if inode == _inode:
                return "inode #%d" % inode
        return self.chooser._for_each_item(find_inode)

    def get_inode(self, dirpath, name):
        self.log_frame()
        if not name.startswith("inode #"):
            return ida_dirtree.direntry_t.BADIDX
        return int(name[7:])

    def get_size(self, inode):
        self.log_frame()
        return 1

    def get_attrs(self, inode):
        self.log_frame()

    def rename_inode(self, inode, newname):
        self.log_frame()
        def set_column0_contents(index, ordinal, _inode):
            if inode == _inode:
                ordinal = self.chooser._get_ordinal_at(index)
                self.chooser.netnode.supset(index, newname, SUPVAL_COL0_DATA_TAG)
                return True
        return self.chooser._for_each_item(set_column0_contents)

    def unlink_inode(self, inode):
        self.log_frame()

ALTVAL_NEW_ORDINAL_TAG = 'L'
ALTVAL_ORDINAL_TAG = 'O'
ALTVAL_INODE_TAG = 'I'
SUPVAL_COL0_DATA_TAG = '0'
SUPVAL_COL1_DATA_TAG = '1'
SUPVAL_COL2_DATA_TAG = '2'


class base_idapython_tree_view_t(ida_kernwin.Choose):

    def __init__(self, title, nitems=100, dirspec_log=True, flags=0):
        flags |= ida_kernwin.CH_MULTI
        flags |= ida_kernwin.CH_HAS_DIRTREE
        ida_kernwin.Choose.__init__(self,
                        title,
                        [
                            ["First",
                             10
                           | ida_kernwin.Choose.CHCOL_PLAIN
                           | ida_kernwin.Choose.CHCOL_DRAGHINT
                           | ida_kernwin.Choose.CHCOL_INODENAME
                            ],
                            ["Second", 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                            ["Third", 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                        ],
                        flags=flags)
        self.debug_items = False
        self.dirspec_log = dirspec_log
        self.dirtree = None
        self.dirspec = None
        self.netnode = ida_netnode.netnode()
        self.netnode.create("$ idapython_tree_view %s" % title)
        for i in range(nitems):
            self._new_item()

    def _get_new_ordinal(self):
        return self.netnode.altval(0, ALTVAL_NEW_ORDINAL_TAG)

    def _set_new_ordinal(self, ordinal):
        self.netnode.altset(0, ordinal, ALTVAL_NEW_ORDINAL_TAG)

    def _allocate_ordinal(self):
        ordinal = self._get_new_ordinal()
        self._set_new_ordinal(ordinal + 1)
        return ordinal

    def _move_items(self, src, dst, sz):
        self.netnode.altshift(src, dst, sz, ALTVAL_ORDINAL_TAG)
        self.netnode.altshift(src, dst, sz, ALTVAL_INODE_TAG)
        self.netnode.supshift(src, dst, sz, SUPVAL_COL0_DATA_TAG)
        self.netnode.supshift(src, dst, sz, SUPVAL_COL1_DATA_TAG)
        self.netnode.supshift(src, dst, sz, SUPVAL_COL2_DATA_TAG)

    def _new_item(self, index=None):
        new_ord = self._allocate_ordinal()
        new_inode = new_ord + 1000
        nitems = self._get_items_count()
        if index is None:
            index = nitems
        else:
            assert(index < nitems)
        if index < nitems:
            self._move_items(index, index + 1, nitems - index)
        self.netnode.altset(index, new_ord, ALTVAL_ORDINAL_TAG)
        self.netnode.altset(index, new_inode, ALTVAL_INODE_TAG)
        return index, new_ord, new_inode

    def _dump_items(self):
        if self.debug_items:
            data = []
            def collect(index, ordinal, inode):
                data.append([inode] + self._make_item_contents_from_index(index))
            self._for_each_item(collect)
            import pprint
            print(pprint.pformat(data))

    def _get_ordinal_at(self, index):
        assert(index <= self.netnode.altlast(ALTVAL_ORDINAL_TAG))
        return self.netnode.altval(index, ALTVAL_ORDINAL_TAG)

    def _get_inode_at(self, index):
        assert(index <= self.netnode.altlast(ALTVAL_INODE_TAG))
        return self.netnode.altval(index, ALTVAL_INODE_TAG)

    def _for_each_item(self, cb):
        for i in range(self._get_items_count()):
            rc = cb(i, self._get_ordinal_at(i), self._get_inode_at(i))
            if rc is not None:
                return rc

    def _get_items_count(self):
        l = self.netnode.altlast(ALTVAL_ORDINAL_TAG)
        return 0 if l == ida_netnode.BADNODE else l + 1

    def _make_item_contents_from_index(self, index):
        ordinal = self._get_ordinal_at(index)
        c0 = self.netnode.supstr(index, SUPVAL_COL0_DATA_TAG) or "a%d" % ordinal
        c1 = self.netnode.supstr(index, SUPVAL_COL1_DATA_TAG) or "b%d" % ordinal
        c2 = self.netnode.supstr(index, SUPVAL_COL2_DATA_TAG) or "c%d" % ordinal
        return [c0, c1, c2]

    def OnGetLine(self, n):
        return self._make_item_contents_from_index(n)

    def OnGetSize(self):
        return self._get_items_count()

    def OnGetDirTree(self):
        self.dirspec = my_dirspec_t(self)
        self.dirtree = ida_dirtree.dirtree_t(self.dirspec)
        def do_link(index, ordinal, inode):
            de = ida_dirtree.direntry_t(inode, False)
            self.dirtree.link("/%s" % self.dirtree.get_entry_name(de))
        self._for_each_item(do_link)
        return (self.dirspec, self.dirtree)

    def OnIndexToInode(self, n):
        return self._get_inode_at(n)

    # Helper function, to be called by "On*" event handlers.
    # This will print all the arguments that were passed
    def _print_prev_frame(self):
        import inspect
        stack = inspect.stack()
        frame, _, _, _, _, _ = stack[1]
        args, _, _, values = inspect.getargvalues(frame)
        print("EVENT: %s: args=%s" % (
            inspect.getframeinfo(frame)[2],
            [(i, values[i]) for i in args[1:]]))

    def OnSelectionChange(self, sel):
        self._print_prev_frame()

    def OnSelectLine(self, sel):
        self._print_prev_frame()


class idapython_tree_view_t(base_idapython_tree_view_t):

    def __init__(self, title, nitems=100, dirspec_log=True, flags=0):
        flags |= ida_kernwin.CH_CAN_INS
        flags |= ida_kernwin.CH_CAN_DEL
        flags |= ida_kernwin.CH_CAN_EDIT
        base_idapython_tree_view_t.__init__(self, title, nitems, dirspec_log, flags)

    def OnInsertLine(self, sel):
        self._print_prev_frame()

        # Add item into storage
        index = sel[0] if sel else None
        prev_inode = self._get_inode_at(index) if index is not None else None
        final_index, new_ordinal, new_inode = self._new_item(sel[0] if sel else None)

        # Link in the tree (unless an absolute path is provided,
        # 'link()' will use the current directory, which is set
        # by the 'OnInsertLine' caller.)
        dt = self.dirtree
        cwd = dt.getcwd()
        parent_de = dt.resolve_path(cwd)
        wanted_rank = -1
        if prev_inode is not None:
            wanted_rank = dt.get_rank(parent_de.idx, ida_dirtree.direntry_t(prev_inode, False))
        de = ida_dirtree.direntry_t(new_inode, False)
        name = dt.get_entry_name(de)
        code = dt.link(name)
        assert(code == ida_dirtree.DTE_OK)
        if wanted_rank >= 0:
            assert(ida_dirtree.dirtree_t.isdir(parent_de))
            cur_rank = dt.get_rank(parent_de.idx, de)
            dt.change_rank(cwd + "/" + name, wanted_rank - cur_rank)
        self._dump_items()
        return [ida_kernwin.Choose.ALL_CHANGED] + [final_index]

    def OnDeleteLine(self, sel):
        self._print_prev_frame()
        dt = self.dirtree
        for index in reversed(sorted(sel)):
            # Note: when it comes to deletion of items, the dirtree_t is
            # designed in such a way folders contents will be re-computed
            # on-demand after the deletion of an inode. Consequently,
            # there is no need to perform an unlink() operation here, only
            # notify the dirtree that something changed
            nitems = self._get_items_count()
            assert(index < nitems)
            inode = self._get_inode_at(index)
            self.netnode.altdel(index, ALTVAL_ORDINAL_TAG)
            self.netnode.altdel(index, ALTVAL_INODE_TAG)
            self._move_items(index + 1, index, nitems - index + 1)
            dt.notify_dirtree(False, inode)
        self._dump_items()
        return [ida_kernwin.Choose.ALL_CHANGED]

    def OnEditLine(self, sel):
        self._print_prev_frame()
        for idx in sel:
            repl = ida_kernwin.ask_str("", 0, "Please enter replacement for index %d" % idx)
            if repl:
                self.netnode.supset(idx, repl, SUPVAL_COL0_DATA_TAG)
        self._dump_items()
        return [ida_kernwin.Choose.ALL_CHANGED] + sel

# -----------------------------------------------------------------------
if __name__ == '__main__':
    form = idapython_tree_view_t("idapython_tree_view_t test", 100)
    form.Show()
