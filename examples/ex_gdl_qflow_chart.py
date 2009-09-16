import idaapi

# -----------------------------------------------------------------------
# Using raw IDAAPI
def raw_main(p=True):
    global q
    f = idaapi.get_func(here())
    if not f:
        return
    q = idaapi.qflow_chart_t("The title", f, 0, 0, idaapi.FC_PREDS)
    for n in xrange(0, q.size()):
        b = q[n]
        if p: print "%x - %x [%d]:" % (b.startEA, b.endEA, n)
        for ns in xrange(0, q.nsucc(n)):
            if p: print "  %d->%d" % (n, q.succ(n, ns))
        for ns in xrange(0, q.npred(n)):
            if p: print "  %d->%d" % (n, q.pred(n, ns))

# -----------------------------------------------------------------------
# Using the class
def cls_main(p=True):
    global f
    f = idaapi.FlowChart(idaapi.get_func(here()))
    for block in f:
        if p: print "%x - %x [%d]:" % (block.startEA, block.endEA, block.id)
        for succ_block in block.succs():
            if p: print "  %x - %x [%d]:" % (succ_block.startEA, succ_block.endEA, succ_block.id)
        for pred_block in block.preds():
            if p: print "  %x - %x [%d]:" % (pred_block.startEA, pred_block.endEA, pred_block.id)

q = None
f = None
raw_main(False)
cls_main(True)

