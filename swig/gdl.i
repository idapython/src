%ignore cancellable_graph_t::check_cancel;
%ignore gdl_graph_t::gen_gdl;
%ignore gdl_graph_t::gen_gdl;
%ignore gdl_graph_t::path;
%ignore gdl_graph_t::path_exists;
%ignore intmap_t::dstr;
%ignore intmap_t::print;
%ignore intseq_t::add_block;
%ignore intseq_t::add_unique;
%ignore intseq_t::del;
%ignore intseq_t::dstr;
%ignore intseq_t::print;
%ignore intseq_t::remove_block;
%ignore intset_t::dstr;
%ignore intset_t::print;
%ignore node_set_t::add;
%ignore node_set_t::extract;
%ignore node_set_t::intersect;
%ignore node_set_t::node_set_t;
%ignore node_set_t::sub;
%ignore qflow_chart_t::blocks;
%ignore flow_chart_t;
%ignore setup_graph_subsystem;
%ignore qbasic_block_t::succ;
%ignore qbasic_block_t::pred;

%include "gdl.hpp"

%extend qflow_chart_t
{
  qbasic_block_t *__getitem__(int n)
  {
    return &(self->blocks[n]);
  }
}

%pythoncode %{
# -----------------------------------------------------------------------
class BasicBlock:
    def __init__(self, id, bb, f):
        self._f = f
        self.id = id
        """Basic block ID"""
        self.startEA = bb.startEA
        """startEA of basic block"""
        self.endEA = bb.endEA
        """endEA of basic block"""
        self.type  = self._f._q.calc_block_type(self.id)
        """Block type (check fc_block_type_t enum)"""

    def preds(self):
        """
        Iteratres the predecessors list
        """
        q = self._f._q
        for i in xrange(0, self._f._q.npred(self.id)):
            yield self._f[q.pred(self.id, i)]

    def succs(self):
        """
        Iteratres the successors list
        """
        q = self._f._q
        for i in xrange(0, q.nsucc(self.id)):
            yield self._f[q.succ(self.id, i)]

# -----------------------------------------------------------------------
class FlowChart:
    """
    Flowchart class used to determine basic blocks
    """
    def __init__(self, f=None, bounds=None, flags=0):
        """
        Constructor
        @param f: A func_t type, use get_func(ea) to get a reference
        @param bounds: A tuple of the form (start, end). Used if "f" is None
        @param flags: one of the FC_xxxx flags. One interesting flag is FC_PREDS
        """
        if (not f) and (not bounds or type(bounds) != types.TupleType):
            raise Exception("Please specifiy either a function or start/end pair")
        if not bounds:
            bounds = (BADADDR, BADADDR)
        # create the flowchart
        self._q = qflow_chart_t("", f, bounds[0], bounds[1], flags)
        self.size = self._q.size()
    def refresh():
        self._q.refresh()
        self.size = self._q.size()
    def __getitem__(self, index):
        """
        Returns a basic block
        @return: BasicBlock
        """
        if index >= self.size:
            raise StopIteration
        return BasicBlock(index, self._q[index], self)


%}
