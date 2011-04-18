%ignore cancellable_graph_t;
%ignore gdl_graph_t;

%ignore intmap_t;
%ignore intset_t;
%ignore intseq_t;
%ignore node_set_t;
%ignore qflow_chart_t::blocks;
%ignore flow_chart_t;
%ignore default_graph_format;
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
#<pycode(py_gdl)>
# -----------------------------------------------------------------------
class BasicBlock(object):
    """Basic block class. It is returned by the Flowchart class"""
    def __init__(self, id, bb, fc):
        self._fc = fc

        self.id = id
        """Basic block ID"""

        self.startEA = bb.startEA
        """startEA of basic block"""

        self.endEA = bb.endEA
        """endEA of basic block"""

        self.type  = self._fc._q.calc_block_type(self.id)
        """Block type (check fc_block_type_t enum)"""

    
    def preds(self):
        """
        Iterates the predecessors list
        """
        q = self._fc._q
        for i in xrange(0, self._fc._q.npred(self.id)):
            yield self._fc[q.pred(self.id, i)]

    
    def succs(self):
        """
        Iterates the successors list
        """
        q = self._fc._q
        for i in xrange(0, q.nsucc(self.id)):
            yield self._fc[q.succ(self.id, i)]

# -----------------------------------------------------------------------
class FlowChart(object):
    """
    Flowchart class used to determine basic blocks.
    Check ex_gdl_qflow_chart.py for sample usage.
    """
    def __init__(self, f=None, bounds=None, flags=0):
        """
        Constructor
        @param f: A func_t type, use get_func(ea) to get a reference
        @param bounds: A tuple of the form (start, end). Used if "f" is None
        @param flags: one of the FC_xxxx flags. One interesting flag is FC_PREDS
        """
        if (f is None) and (bounds is None or type(bounds) != types.TupleType):
            raise Exception("Please specifiy either a function or start/end pair")
        
        if bounds is None:
            bounds = (BADADDR, BADADDR)
            
        # Create the flowchart
        self._q = qflow_chart_t("", f, bounds[0], bounds[1], flags)
    
    size = property(lambda self: self._q.size())
    """Number of blocks in the flow chart"""
    

    def refresh():
        """Refreshes the flow chart"""
        self._q.refresh()


    def _getitem(self, index):
        return BasicBlock(index, self._q[index], self)        
    
    
    def __iter__(self):
        return (self._getitem(index) for index in xrange(0, self.size))
    
    
    def __getitem__(self, index):
        """
        Returns a basic block

        @return: BasicBlock
        """
        if index >= self.size:
            raise KeyError
        else:    
            return self._getitem(index)

#</pycode(py_gdl)>
%}
