import idaapi
from idaapi import Choose2

#<pycode(py_choose2ex1)>


class chooser_handler_t(idaapi.action_handler_t):
    def __init__(self, thing):
        idaapi.action_handler_t.__init__(self)
        self.thing = thing

    def activate(self, ctx):
        sel = []
        for i in xrange(len(ctx.chooser_selection)):
            sel.append(str(ctx.chooser_selection.at(i)))
        print "command %s selected @ %s" % (self.thing, ", ".join(sel))

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if idaapi.is_chooser_tform(ctx.form_type) else idaapi.AST_DISABLE_FOR_FORM


class MyChoose2(Choose2):

    def __init__(self, title, nb = 5, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose2.__init__(
            self,
            title,
            [ ["Address", 10], ["Name", 30] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.n = 0
        self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.icon = 5
        self.selcount = 0
        self.modal = modal
        self.popup_names = ["Inzert", "Del leet", "Ehdeet", "Ree frech"]

        print("created %s" % str(self))

    def OnClose(self):
        print "closed", str(self)

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"
        print("editing %d" % n)

    def OnInsertLine(self):
        self.items.append(self.make_item())
        print("insert line")

    def OnSelectLine(self, n):
        self.selcount += 1
        Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        print("getline %d" % n)
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        print("getsize -> %d" % n)
        return n

    def OnDeleteLine(self, n):
        print("del %d " % n)
        del self.items[n]
        return n

    def OnRefresh(self, n):
        print("refresh %d" % n)
        return n

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        print "geticon", n, t
        return t

    def show(self):
        return self.Show(self.modal) >= 0

    def make_item(self):
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r

    def OnGetLineAttr(self, n):
        print("getlineattr %d" % n)
        if n == 1:
            return [0xFF0000, 0]


# -----------------------------------------------------------------------
def test_choose2(modal=False):
    global c
    c = MyChoose2("Choose2 - sample 1", nb=10, modal=modal)
    r = c.show()
    form = idaapi.get_current_tform()
    for thing in ["A", "B"]:
        idaapi.attach_action_to_popup(form, None, "choose2:act%s" % thing)

# -----------------------------------------------------------------------
def test_choose2_embedded():
    global c
    c = MyChoose2("Choose2 - embedded", nb=12, embedded = True, width=123, height=222)
    r = c.Embedded()
    if r == 1:
        try:
            if test_embedded:
                o, sel = _idaapi.choose2_get_embedded(c)
                print("o=%s, type(o)=%s" % (str(o), type(o)))
                test_embedded(o)
        finally:
            c.Close()

# -----------------------------------------------------------------------
if __name__ == '__main__':

    # Register actions
    for thing in ["A", "B"]:
        actname = "choose2:act%s" % thing
        idaapi.register_action(
            idaapi.action_desc_t(
                actname,
                "command %s" % thing,
                chooser_handler_t(thing)))

    #test_choose2_embedded()
    test_choose2(False)

#</pycode(py_choose2ex1)>
