"""
summary: Record and replay changes in function prototypes

description:
    This is a sample script, that will record (in memory) all changes in
    functions prototypes, in order to re-apply them later.

    To use this script:
     - open an IDB (say, "test.idb")
     - modify some functions prototypes (e.g., by triggering the 'Y'
       shortcut when the cursor is placed on the first address of a
       function)
     - reload that IDB, *without saving it first*
     - call rpc.replay(), to re-apply the modifications.

    Note: 'ti_changed' is also called for changes to the function
    frames, but we'll only record function prototypes changes.
"""
import ida_idp
import ida_funcs
import ida_typeinf

class replay_prototypes_changes_t(ida_idp.IDB_Hooks):
    def __init__(self):
        ida_idp.IDB_Hooks.__init__(self)
        # we'll store tuples (ea, typ, fields). We cannot store
        # tinfo_t instances in there, because tinfo_t's are only
        # valid while the IDB is opened.
        # Since the very purpose of this example is to re-apply
        # types after the IDB has been closed & re-opened, we
        # must therefore keep the serialized version only.
        self.memo = []
        self.replaying = False

    def _deser(self, typ, fields):
        tif = ida_typeinf.tinfo_t()
        if not tif.deserialize(ida_typeinf.get_idati(), typ, fields):
            tif = None
        return tif

    def ti_changed(self, ea, typ, fields):
        if not self.replaying:
            pfn = ida_funcs.get_func(ea)
            if pfn and pfn.start_ea == ea:
                self.memo.append((ea, typ, fields))

                # de-serialize, just for the sake of printing
                tif = self._deser(typ, fields)
                if tif:
                    print("%x: type changed: %s" % (
                        ea,
                        tif._print(None, ida_typeinf.PRTYPE_1LINE)))

    def replay(self):
        self.replaying = True
        try:
            for ea, typ, fields in self.memo:
                tif = self._deser(typ, fields)
                if tif:
                    print("%x: applying type: %s" % (
                        ea,
                        tif._print(None, ida_typeinf.PRTYPE_1LINE)))
                    # Since that type information was remembered from a change
                    # the user made, we'll re-apply it as a definite type (i.e.,
                    # can't be overriden by IDA's auto-analysis/heuristics.)
                    apply_flags = ida_typeinf.TINFO_DEFINITE
                    if not ida_typeinf.apply_tinfo(ea, tif, apply_flags):
                        print("FAILED")
        finally:
            self.replaying = False

rpc = replay_prototypes_changes_t()
if rpc.hook():
    print("""
Please modify some functions prototypes (press 'Y' when the
cursor is on the function name, or first address), and when
you are done reload this IDB, *WITHOUT* saving it first,
and type 'rpc.replay()'
""")
else:
    print("Couldn't create hooks")
