import idaapi
from idaapi import Choose2

class MyChoose2(Choose2):

    def __init__(self, title, nb = 5):
        Choose2.__init__(self, title, [ ["Address", 10], ["Name", 30] ])
        self.n = 0
        self.items = [ self.make_item() for x in xrange(0, nb+1) ]
        self.icon = 5
        self.selcount = 0
        self.popup_names = ["Inzert", "Del leet", "Ehdeet", "Ree frech"]
        print "created", str(self)

    def OnClose(self):
        print "closed", str(self)

    def OnEditLine(self, n):
        self.items[n][1] = self.items[n][1] + "*"
        print "editing", str(n)

    def OnInsertLine(self):
        self.items.append(self.make_item())
        print "insert line"

    def OnSelectLine(self, n):
        self.selcount += 1
        Warning("[%02d] selectline '%s'" % (self.selcount, n))

    def OnGetLine(self, n):
        print "getline", str(n)
        return self.items[n]

    def OnGetSize(self):
        print "getsize"
        return len(self.items)

    def OnDeleteLine(self, n):
        print "del ",str(n)
        del self.items[n]
        return n

    def OnRefresh(self, n):
        print "refresh", n
        return n

    def OnCommand(self, n, cmd_id):
        if cmd_id == self.cmd_a:
            print "command A selected @", n
        elif cmd_id == self.cmd_b:
            print "command B selected @", n
        else:
            print "Unknown command:", cmd_id, "@", n
        return 1

    def OnGetIcon(self, n):
        r = self.items[n]
        t = self.icon + r[1].count("*")
        print "geticon", n, t
        return t

    def show(self):
        t = self.Show()
        if t < 0:
            return False
        self.cmd_a = self.AddCommand("command A")
        self.cmd_b = self.AddCommand("command B")
        return True

    def make_item(self):
        r = [str(self.n), "func_%04d" % self.n]
        self.n += 1
        return r

    def OnGetLineAttr(self, n):
        print "getlineattr", n
        if n == 1:
            return [0xFF0000, 0]

for i in xrange(1, 5+1):
    c = MyChoose2("choose2 - sample %d" % i, i*2)
    r = c.show()
    print r
    