"""
summary: A widget showing data in a tabular fashion

description:
  Shows how to subclass the ida_kernwin.Choose class to
  show data organized in a simple table.
  In addition, registers a couple actions that can be applied to it.

keywords: chooser, actions

see_also: choose_multi, chooser_with_folders
"""

import ida_kernwin
from ida_kernwin import Choose

# -----------------------------------------------------------------------
class chooser_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, thing):
        ida_kernwin.action_handler_t.__init__(self)
        self.thing = thing

    def activate(self, ctx):
        sel = []
        for idx in ctx.chooser_selection:
            sel.append(str(idx))
        print("command %s selected @ %s" % (self.thing, ", ".join(sel)))

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ida_kernwin.is_chooser_widget(ctx.widget_type) \
          else ida_kernwin.AST_DISABLE_FOR_WIDGET

    @staticmethod
    def compose_action_name(v):
        return "choose:act%s" % v


# create actions
actions_variants = ["A", "B"]
for av in actions_variants:
    actname = chooser_handler_t.compose_action_name(av)
    if ida_kernwin.unregister_action(actname):
        print("Unregistered previously-registered action \"%s\"" % actname)

    desc = ida_kernwin.action_desc_t(actname, "command %s" % av, chooser_handler_t(av))
    if ida_kernwin.register_action(desc):
        print("Registered action \"%s\"" % actname)


# -----------------------------------------------------------------------
class MyChoose(Choose):

    def __init__(self, title, nb = 5, flags = 0,
                 modal = False,
                 embedded = False, width = None, height = None):
        Choose.__init__(
            self,
            title,
            [ ["Address", 10], ["Name", 30] ],
            flags = flags | Choose.CH_RESTORE
                          | (Choose.CH_CAN_INS
                           | Choose.CH_CAN_DEL
                           | Choose.CH_CAN_EDIT
                           | Choose.CH_CAN_REFRESH),
            embedded = embedded,
            width = width,
            height = height)
        self.n = 0
        self.items = [ self.make_item() for x in range(nb) ]
        self.icon = 5
        self.selcount = 0
        self.modal = modal
        self.popup_names = ["Inzert", "Del leet", "Ehdeet", "Ree frech"]

        print("created %s" % str(self))

    def OnInit(self):
        print("inited", str(self))
        return True

    def OnGetSize(self):
        n = len(self.items)
        print("getsize -> %d" % n)
        return n

    def OnGetLine(self, n):
        print("getline %d" % n)
        return self.items[n]

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        print("geticon", n, t)
        return t

    def OnGetLineAttr(self, n):
        print("getlineattr %d" % n)
        if n == 1:
            return [0xFF0000, 0]

    def OnInsertLine(self, n):
        # we ignore current selection
        n = self.n # position at the just added item
        self.items.append(self.make_item())
        print("insert line")
        return (Choose.ALL_CHANGED, n)

    def OnDeleteLine(self, n):
        print("del %d " % n)
        del self.items[n]
        return [Choose.ALL_CHANGED] + self.adjust_last_item(n)

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"
        print("editing %d" % n)
        return (Choose.ALL_CHANGED, n)

    def OnRefresh(self, n):
        print("refresh %d" % n)
        return None # call standard refresh

    def OnSelectLine(self, n):
        self.selcount += 1
        warning("[%02d] selectline '%d'" % (self.selcount, n))
        return (Choose.NOTHING_CHANGED, )

    def OnClose(self):
        print("closed", str(self))

    def show(self):
        ok = self.Show(self.modal) >= 0
        if ok:
            # permanently attach actions to this chooser's popup menu
            for av in actions_variants:
                actname = chooser_handler_t.compose_action_name(av)
                ida_kernwin.attach_action_to_popup(self.GetWidget(), None, actname)
        return ok

    def make_item(self):
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r


# -----------------------------------------------------------------------
def test_choose(modal = False, nb = 10):
    global c
    c = MyChoose("Choose - sample 1", nb = nb, modal = modal)
    c.show()

# -----------------------------------------------------------------------
def test_choose_embedded():
    global c
    c = MyChoose("Choose - embedded", nb=12, embedded = True, width=123, height=222)
    r = c.Embedded()
    if r == 0:
        try:
            if test_embedded:
                o, sel = _idaapi.choose_get_embedded(c)
                print("o=%s, type(o)=%s" % (str(o), type(o)))
                test_embedded(o)
        finally:
            c.Close()

# -----------------------------------------------------------------------
if __name__ == '__main__':
    #test_choose_embedded()
    test_choose(False)
