%{
#include <graph.hpp>
%}

// "Warning 305: Bad constant value (ignored).", on:
// #define GCC_PUREVIRT = 0
#pragma SWIG nowarn=305

// "Warning 473: Returning a pointer or reference in a director method is not recommended."
%warnfilter(473) mutable_graph_t::nrect;
%warnfilter(473) place_t::clone;
%warnfilter(473) place_t::makeplace;
%warnfilter(473) place_t::name;
%warnfilter(473) place_t::enter;

// "Warning 517: Director class 'mutable_graph_t' can't be constructed"
%warnfilter(517) mutable_graph_t;

// most of these aren't defined/exported through graph.hpp
%ignore abstract_graph_t::callback;
%ignore abstract_graph_t;
%ignore edge_info_t::add_layout_point;
%ignore edge_infos_wrapper_t::edge_infos_wrapper_t;
%ignore edge_infos_wrapper_t::~edge_infos_wrapper_t;
%ignore graph_dispatcher;
%ignore graph_item_t::operator==;
%ignore mutable_graph_t::add_edge;
%ignore mutable_graph_t::add_node;
%ignore mutable_graph_t::calc_center_of;
%ignore mutable_graph_t::change_visibility;
%ignore mutable_graph_t::check_new_group;
%ignore mutable_graph_t::clone;
%ignore mutable_graph_t::del_edge;
%ignore mutable_graph_t::del_node;
%ignore mutable_graph_t::fix_collapsed_group_edges;
%ignore mutable_graph_t::get_edge(edge_t);
%rename (get_edge) my_get_edge;
%ignore mutable_graph_t::groups_are_present;
%ignore mutable_graph_t::insert_simple_nodes;
%ignore mutable_graph_t::insert_visible_nodes;
%ignore mutable_graph_t::move_grouped_nodes;
%ignore mutable_graph_t::move_to_same_place;
%ignore mutable_graph_t::mutable_graph_t;
%ignore mutable_graph_t::redo_layout;
%ignore mutable_graph_t::refresh;
%ignore mutable_graph_t::replace_edge;
%ignore mutable_graph_t::resize;
%ignore mutable_graph_t::set_nrect;
%ignore node_ordering_t::clr;
%ignore node_ordering_t::order;
%ignore point_t::dstr;
%ignore point_t::print;
%ignore pointseq_t::dstr;
%ignore pointseq_t::print;
%ignore rect_t::operator<;
%ignore selection_item_t::selection_item_t(class graph_item_t &);
%feature("nodirector") user_graph_place_t;

%extend graph_visitor_t {
public:
  virtual int idaapi visit_node(int /*n*/, rect_t & /*r*/) { qnotused(self); return 0; }
  virtual int idaapi visit_edge(edge_t /*e*/, edge_info_t * /*ei*/) { qnotused(self); return 0; }
}

%extend mutable_graph_t {
public:
  virtual edge_info_t my_get_edge(edge_t e)
  {
    return *($self->get_edge(e));
  }
}

%template(screen_graph_selection_base_t) qvector<selection_item_t>;
%template(node_layout_t) qvector<rect_t>;
%template(pointvec_t) qvector<point_t>;

%include "graph.hpp"
%ignore graph_visitor_t::visit_node;
%ignore graph_visitor_t::visit_edge;

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
