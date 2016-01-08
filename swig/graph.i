%ignore mutable_graph_t;
%ignore graph_visitor_t;
%ignore abstract_graph_t;
%include "graph.hpp"

%{
//<code(py_graph)>
//</code(py_graph)>
%}

%inline %{
//<inline(py_graph)>
//</inline(py_graph)>
%}

%pythoncode %{
#<pycode(py_graph)>
#</pycode(py_graph)>
%}
