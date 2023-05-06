
import idaapi

class Data_t:
    def children(self, path):
        num_children = self._simple_hash(path) & 0x7
        num_folders  = num_children >> 1

        for n in range(num_folders):
            yield True, "Folder %d" % (n + 1)
        for n in range(num_children - num_folders):
            yield False, "Item %d" % (n + 1)

    def _simple_hash(self, path):
        s = 0
        for c in path:
            s += ord(c)
        return s

#-----------------------

# dirspec for the dirtree
class my_dirspec_t(idaapi.dirspec_t):
    def __init__(self):
        idaapi.dirspec_t.__init__(self)
        self.inodes = []
        self.name_index = {}

    def add_entry(self, dirpath, name):
        new_inode = len(self.inodes)
        self.inodes.append(name)
        self.name_index[dirpath, name] = new_inode
        return new_inode

    def get_name(self, inode, flags=0):
        if inode >= 0 and inode < len(self.inodes):
            return self.inodes[inode]

    def get_inode(self, dirpath, name):
        return self.name_index.get((dirpath, name), idaapi.direntry_t.BADIDX)

    def n_inodes(self):
        return len(self.inodes)

    def get_attrs(self, inode):
        pass

    def rename_inode(self, inode, newname):
        pass

    def unlink_inode(self, inode):
        pass

# chooser with dirtree, lazy-loaded
class my_tree_t(idaapi.Choose):
    inherited = idaapi.Choose

    def __init__(self):
        self.dirspec = my_dirspec_t()
        self.dirtree = idaapi.dirtree_t(self.dirspec)

        self.data = Data_t()

        flags = idaapi.CH_TM_FULL_TREE
        columns = [
            ["Name", 10 | idaapi.CHCOL_PLAIN]
        ]

        self.inherited.__init__(self, "My tree", columns, flags)

    def OnGetSize(self):
        return self.dirspec.n_inodes()

    def OnGetLine(self, index):
        inode = self.OnIndexToInode(index)
        return [self.dirspec.get_name(inode)]

    def OnGetDirTree(self):
        return self.dirspec, self.dirtree

    def OnIndexToInode(self, n):
        return n

    # TODO: add "dirtree" parameter when the pywraps are ready
    def OnLazyLoadDir(self, dir_path):
        dirtree = self.dirtree  # should use the parameter when ready

        for is_dir, entry in self.data.children(dir_path):
            if is_dir:
                dirtree.mkdir(entry)
            else:
                inode = self.dirspec.add_entry(dir_path, entry)
                dirtree.link(inode)
        return True

# plugin
class lazy_chooser_plugin_t(idaapi.plugin_t):
    flags = 0
    comment = "This is a comment."
    help = "This is a test."
    wanted_name = "Test a lazy-loader chooser in Python"
    wanted_hotkey = "Alt-Shift-F12"

    def init(self):
        self.tree = my_tree_t()
        print("Registered plugin test-lazy-chooser");
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.tree.Show()

    def term(self):
        print("Un-registered plugin test-lazy-chooser");

def PLUGIN_ENTRY():
    return lazy_chooser_plugin_t()

