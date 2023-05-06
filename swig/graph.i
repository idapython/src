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
%ignore abstract_graph_t::vgrcall;
%ignore abstract_graph_t::clear;
%ignore abstract_graph_t::dump_graph;
%ignore abstract_graph_t::calc_bounds;
%ignore abstract_graph_t::calc_fitting_params;
%ignore abstract_graph_t::for_all_nodes_edges;
%ignore abstract_graph_t::get_edge_ports;
%ignore abstract_graph_t::add_node_edges;
%ignore abstract_graph_t::create_polar_tree_layout;
%ignore abstract_graph_t::create_radial_tree_layout;
%ignore abstract_graph_t::create_orthogonal_layout;
%ignore abstract_graph_t::clone;
%ignore abstract_graph_t::nrect;
%rename (nrect) novirt_nrect;
%ignore abstract_graph_t::get_edge;
%rename (get_edge) novirt_get_edge;

%ignore edge_info_t::add_layout_point;
%ignore edge_infos_wrapper_t::edge_infos_wrapper_t;
%ignore edge_infos_wrapper_t::~edge_infos_wrapper_t;
%ignore graph_dispatcher;
%ignore graph_item_t::operator==;

// Meant to be constructed by the kernel/ui only
%feature("nodirector") mutable_graph_t;
%ignore mutable_graph_t::mutable_graph_t;
%ignore mutable_graph_t::calc_center_of;
%ignore mutable_graph_t::change_visibility;
%ignore mutable_graph_t::check_new_group;
%ignore mutable_graph_t::groups_are_present;
%ignore mutable_graph_t::insert_simple_nodes;
%ignore mutable_graph_t::insert_visible_nodes;
%ignore mutable_graph_t::move_grouped_nodes;
%ignore mutable_graph_t::move_to_same_place;

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

%extend abstract_graph_t {
public:
  edge_info_t *novirt_get_edge(edge_t e)
  {
    return $self->get_edge(e);
  }
  rect_t novirt_nrect(int n)
  {
    return $self->nrect(n);
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
