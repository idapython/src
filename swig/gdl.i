%{
#include <gdl.hpp>
%}

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
#</pycode(py_gdl)>
%}
