%{
#include <gdl.hpp>
%}

%ignore gdl_graph_t::gen_gdl;
%ignore gdl_graph_t::gen_dot;
%ignore gdl_graph_t::path_exists;

%ignore cancellable_graph_t::padding;
%ignore cancellable_graph_t::check_cancel;

%ignore intmap_t;
%ignore intset_t;
%ignore intseq_t;
%ignore node_set_t;
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
#<pycode(py_gdl)>
#</pycode(py_gdl)>
%}
