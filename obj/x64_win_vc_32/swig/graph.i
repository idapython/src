%module(docstring="IDA Plugin SDK API wrapper: graph",directors="1",threads="1") ida_graph
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_GRAPH
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_GRAPH
  #define HAS_DEP_ON_INTERFACE_GRAPH
#endif
%include "header.i"
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
  virtual int idaapi visit_node(int /*n*/, rect_t & /*r*/) { return 0; }
  virtual int idaapi visit_edge(edge_t /*e*/, edge_info_t * /*ei*/) { return 0; }
}

%extend mutable_graph_t {
public:
  virtual edge_info_t my_get_edge(edge_t e)
  {
    return *($self->get_edge(e));
  }
}

%template(node_layout_t) qvector<rect_t>;
%template(pointvec_t) qvector<point_t>;

%include "graph.hpp"
%ignore graph_visitor_t::visit_node;
%ignore graph_visitor_t::visit_edge;

%{
//<code(py_graph)>
class py_graph_t : public py_customidamemo_t
{
  typedef py_customidamemo_t inherited;

protected:
  void collect_class_callbacks_ids(pycim_callbacks_ids_t *out);

private:
  enum
  {
    GRCODE_HAVE_HINT             = 0x00010000,
    GRCODE_HAVE_EDGE_HINT        = 0x00020000,
    GRCODE_HAVE_CLICKED          = 0x00040000,
    GRCODE_HAVE_DBL_CLICKED      = 0x00080000,
    GRCODE_HAVE_GOTFOCUS         = 0x00100000,
    GRCODE_HAVE_LOSTFOCUS        = 0x00200000,
    GRCODE_HAVE_CHANGED_CURRENT  = 0x00400000,
    GRCODE_HAVE_CREATING_GROUP   = 0x00800000,
    GRCODE_HAVE_DELETING_GROUP   = 0x01000000,
    GRCODE_HAVE_GROUP_VISIBILITY = 0x02000000,
  };
  struct nodetext_cache_t
  {
    qstring text;
    bgcolor_t bgcolor;
    nodetext_cache_t(const nodetext_cache_t &rhs): text(rhs.text), bgcolor(rhs.bgcolor) {}
    nodetext_cache_t(const char *t, bgcolor_t c): text(t), bgcolor(c) {}
    nodetext_cache_t() {}
  };

  class nodetext_cache_map_t: public std::map<int, nodetext_cache_t>
  {
  public:
    nodetext_cache_t *get(int node_id)
    {
      iterator it = find(node_id);
      if ( it == end() )
        return NULL;
      return &it->second;
    }
    nodetext_cache_t *add(const int node_id, const char *text, bgcolor_t bgcolor = DEFCOLOR)
    {
      return &(insert(std::make_pair(node_id, nodetext_cache_t(text, bgcolor))).first->second);
    }
  };

  bool refresh_needed;
  nodetext_cache_map_t node_cache;

  // instance callback
  ssize_t gr_callback(int code, va_list va);

  // static callback
  static ssize_t idaapi s_callback(void *obj, int code, va_list va)
  {
    // don't perform sanity check for 'grcode_destroyed', since if we called
    // Close() on this object, it'll have been marked for later deletion in the
    // UI, and thus when we end up here, the view has already been destroyed.
    bool found = pycim_lookup_info.find_by_py_view(NULL, (py_graph_t *) obj);
    QASSERT(30453, found || code == grcode_destroyed);
    if ( found )
    {
      PYW_GIL_GET;
      return ((py_graph_t *)obj)->gr_callback(code, va);
    }
    else
    {
      return 0;
    }
  }

  // Refresh user-defined graph node number and edges
  // It calls Python method and expects that the user already filled
  // the nodes and edges. The nodes and edges are retrieved and passed to IDA
  void on_user_refresh(mutable_graph_t *g);

  // Retrieves the text for user-defined graph node
  // It expects either a string or a tuple (string, bgcolor)
  bool on_user_text(mutable_graph_t * /*g*/, int node, const char **str, bgcolor_t *bg_color);

  // Retrieves the hint for the user-defined graph
  // Calls Python and expects a string or None
  int on_hint(char **hint, int node);
  int on_edge_hint(char **hint, int src, int dest);
  int _on_hint_epilog(char **hint, ref_t result);

  // graph is being destroyed
  void on_graph_destroyed(mutable_graph_t * /*g*/ = NULL)
  {
    refresh_needed = true;
    node_cache.clear();
  }

  // graph is being clicked
  int on_clicked(
        graph_viewer_t * /*view*/,
        selection_item_t * /*item1*/,
        graph_item_t *item2)
  {
    // in:  graph_viewer_t *view
    //      selection_item_t *current_item1
    //      graph_item_t *current_item2
    // out: 0-ok, 1-ignore click
    // this callback allows you to ignore some clicks.
    // it occurs too early, internal graph variables are not updated yet
    // current_item1, current_item2 point to the same thing
    // item2 has more information.
    // see also: kernwin.hpp, custom_viewer_click_t
    if ( item2->n == -1 )
      return 1;

    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_CLICK,
                    "i",
                    item2->n));
    PyW_ShowCbErr(S_ON_CLICK);
    return result == NULL || !PyObject_IsTrue(result.o);
  }

  // a graph node has been double clicked
  int on_dblclicked(graph_viewer_t * /*view*/, selection_item_t *item)
  {
    // in:  graph_viewer_t *view
    //      selection_item_t *current_item
    // out: 0-ok, 1-ignore click
    //graph_viewer_t *v   = va_arg(va, graph_viewer_t *);
    //selection_item_t *s = va_arg(va, selection_item_t *);
    if ( item == NULL || !item->is_node )
      return 1;

    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_DBL_CLICK,
                    "i",
                    item->node));
    PyW_ShowCbErr(S_ON_DBL_CLICK);
    return result == NULL || !PyObject_IsTrue(result.o);
  }

  // a graph viewer got focus
  void on_gotfocus(graph_viewer_t * /*view*/)
  {
    if ( self.o == NULL )
      return;

    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_ACTIVATE,
                    NULL));
    PyW_ShowCbErr(S_ON_ACTIVATE);
  }

  // a graph viewer lost focus
  void on_lostfocus(graph_viewer_t * /*view*/)
  {
    if ( self.o == NULL )
      return;

    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_DEACTIVATE,
                    NULL));
    PyW_ShowCbErr(S_ON_DEACTIVATE);
  }

  // a new graph node became the current node
  int on_changed_current(graph_viewer_t * /*view*/, int curnode)
  {
    // in:  graph_viewer_t *view
    //      int curnode
    // out: 0-ok, 1-forbid to change the current node
    if ( curnode < 0 )
      return 0;

    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_SELECT,
                    "i",
                    curnode));
    PyW_ShowCbErr(S_ON_SELECT);
    return !(result != NULL && PyObject_IsTrue(result.o));
  }

  // a group is being created
  int on_creating_group(mutable_graph_t *my_g, intvec_t *my_nodes)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    newref_t py_nodes(PyList_New(my_nodes->size()));
    int i;
    intvec_t::const_iterator p;
    for ( i = 0, p=my_nodes->begin(); p != my_nodes->end(); ++p, ++i )
      PyList_SetItem(py_nodes.o, i, IDAPyInt_FromLong(*p));
    newref_t py_result(
            PyObject_CallMethod(
                    self.o,
                    (char *)S_ON_CREATING_GROUP,
                    "O",
                    py_nodes.o));
    PyW_ShowCbErr(S_ON_CREATING_GROUP);
    return (py_result == NULL || !IDAPyInt_Check(py_result.o)) ? 1 : IDAPyInt_AsLong(py_result.o);
  }

  // a group is being deleted
  int on_deleting_group(mutable_graph_t * /*g*/, int old_group)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    // TODO
    return 0;
  }

  // a group is being collapsed/uncollapsed
  int on_group_visibility(mutable_graph_t * /*g*/, int group, bool expand)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();
    // TODO
    return 0;
  }


  void show()
  {
    TWidget *view;
    if ( pycim_lookup_info.find_by_py_view(&view, this) )
      display_widget(view, WOPN_TAB);
  }

  void jump_to_node(int nid)
  {
    ref_t nodes(PyW_TryGetAttrString(self.o, S_M_NODES));
    if ( nid >= PyList_Size(nodes.o) )
      return;

    viewer_center_on(view, nid);
    int x, y;

    // will return a place only when a node was previously selected
    place_t *old_pl = get_custom_viewer_place(view, false, &x, &y);
    if ( old_pl != NULL )
    {
      user_graph_place_t *new_pl = (user_graph_place_t *) old_pl->clone();
      new_pl->node = nid;
      jumpto(view, new_pl, x, y);
      delete new_pl;
    }
  }

  virtual void refresh()
  {
    refresh_needed = true;
    inherited::refresh();
  }

  int initialize(PyObject *self, const char *title)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    if ( !collect_pyobject_callbacks(self) )
      return -1;

    TWidget *widget = find_widget(title);
    if ( widget == NULL ) // create new widget
    {
      lookup_entry_t &e = pycim_lookup_info.new_entry(this);
      // get a unique graph id
      netnode id;
      char grnode[MAXSTR];
      qsnprintf(grnode, sizeof(grnode), "$ pygraph %s", title);
      id.create(grnode);
      // pre-bind 'self', so that 'on_user_refresh()' can complete
      this->self = borref_t(self);
      graph_viewer_t *pview = create_graph_viewer(title, id, s_callback, this, 0);
      this->self = ref_t();
      display_widget(pview, WOPN_TAB);
      newref_t ret(PyObject_CallMethod(self, "hook", NULL));
      if ( pview != NULL )
        viewer_fit_window(pview);
      bind(self, pview);
      pycim_lookup_info.commit(e, view);
    }
    else
    {
      show();
    }

    viewer_fit_window(view);
    return 0;
  }

public:
  py_graph_t()
  {
    // form = NULL;
    refresh_needed = true;
  }

  static void SelectNode(PyObject *self, int nid)
  {
    if ( nid < 0 )
      return;

    py_graph_t *_this = view_extract_this<py_graph_t>(self);
    if ( _this == NULL || !pycim_lookup_info.find_by_py_view(NULL, _this) )
      return;

    _this->jump_to_node(nid);
  }

  static py_graph_t *Close(PyObject *self)
  {
    TWidget *view;
    py_graph_t *_this = view_extract_this<py_graph_t>(self);
    if ( _this == NULL || !pycim_lookup_info.find_by_py_view(&view, _this) )
      return NULL;
    newref_t ret(PyObject_CallMethod(self, "unhook", NULL));
    close_widget(view, WCLS_CLOSE_LATER);
    return _this;
  }

  static py_graph_t *Show(PyObject *self)
  {
    PYW_GIL_CHECK_LOCKED_SCOPE();

    py_graph_t *py_graph = view_extract_this<py_graph_t>(self);

    // New instance?
    if ( py_graph == NULL )
    {
      qstring title;
      if ( !PyW_GetStringAttr(self, S_M_TITLE, &title) )
        return NULL;

      // Form already created? try to get associated py_graph instance
      // so that we reuse it
      TWidget *existing = find_widget(title.c_str());
      if ( existing != NULL )
        pycim_lookup_info.find_by_view((py_customidamemo_t**) &py_graph, existing);

      if ( py_graph == NULL )
      {
        py_graph = new py_graph_t();
      }
      else
      {
        // unbind so we are rebound
        py_graph->unbind(false);
        py_graph->refresh_needed = true;
      }
      if ( py_graph->initialize(self, title.c_str()) < 0 )
      {
        delete py_graph;
        py_graph = NULL;
      }
    }
    else
    {
      py_graph->show();
    }
    return py_graph;
  }
};

//-------------------------------------------------------------------------
void py_graph_t::collect_class_callbacks_ids(pycim_callbacks_ids_t *out)
{
  inherited::collect_class_callbacks_ids(out);
  out->add(S_ON_REFRESH, 0);
  out->add(S_ON_GETTEXT, 0);
  out->add(S_M_EDGES, -1);
  out->add(S_M_NODES, -1);
  out->add(S_ON_HINT, GRCODE_HAVE_HINT);
  out->add(S_ON_EDGE_HINT, GRCODE_HAVE_EDGE_HINT);
  out->add(S_ON_CLICK, GRCODE_HAVE_CLICKED);
  out->add(S_ON_DBL_CLICK, GRCODE_HAVE_DBL_CLICKED);
  out->add(S_ON_SELECT, GRCODE_HAVE_CHANGED_CURRENT);
  out->add(S_ON_ACTIVATE, GRCODE_HAVE_GOTFOCUS);
  out->add(S_ON_DEACTIVATE, GRCODE_HAVE_LOSTFOCUS);
  out->add(S_ON_CREATING_GROUP, GRCODE_HAVE_CREATING_GROUP);
  out->add(S_ON_DELETING_GROUP, GRCODE_HAVE_DELETING_GROUP);
  out->add(S_ON_GROUP_VISIBILITY, GRCODE_HAVE_GROUP_VISIBILITY);
}

//-------------------------------------------------------------------------
void py_graph_t::on_user_refresh(mutable_graph_t *g)
{
  if ( !refresh_needed )
    return;

  // Check return value to OnRefresh() call
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t ret(PyObject_CallMethod(self.o, (char *)S_ON_REFRESH, NULL));
  PyW_ShowCbErr(S_ON_REFRESH);
  if ( ret != NULL && PyObject_IsTrue(ret.o) )
  {
    // Refer to the nodes
    ref_t nodes(PyW_TryGetAttrString(self.o, S_M_NODES));
    if ( ret != NULL && PyList_Check(nodes.o) )
    {
      // Refer to the edges
      ref_t edges(PyW_TryGetAttrString(self.o, S_M_EDGES));
      if ( ret != NULL && PyList_Check(edges.o) )
      {
        // Resize the nodes
        int max_nodes = abs(int(PyList_Size(nodes.o)));
        g->clear();
        g->resize(max_nodes);

        // Mark that we refreshed already
        refresh_needed = false;

        // Clear cached nodes
        node_cache.clear();

        // Get the edges
        for ( int i=(int)PyList_Size(edges.o)-1; i >= 0; i-- )
        {
          // Each list item is a sequence (id1, id2)
          borref_t item(PyList_GetItem(edges.o, i));
          if ( !PySequence_Check(item.o) )
            continue;

          // Get and validate each of the two elements in the sequence
          int edge_ids[2];
          int j;
          for ( j=0; j < qnumber(edge_ids); j++ )
          {
            newref_t id(PySequence_GetItem(item.o, j));
            if ( id == NULL || !IDAPyInt_Check(id.o) )
              break;
            int v = int(PyInt_AS_LONG(id.o));
            if ( v > max_nodes )
              break;
            edge_ids[j] = v;
          }

          // Incomplete?
          if ( j != qnumber(edge_ids) )
            break;

          // Add the edge
          g->add_edge(edge_ids[0], edge_ids[1], NULL);
        }
      }
    }
  }
}

//-------------------------------------------------------------------------
bool py_graph_t::on_user_text(mutable_graph_t * /*g*/, int node, const char **str, bgcolor_t *bg_color)
{
  // If already cached then return the value
  nodetext_cache_t *c = node_cache.get(node);
  if ( c != NULL )
  {
    *str = c->text.c_str();
    if ( bg_color != NULL )
      *bg_color = c->bgcolor;
    return true;
  }

  // Not cached, call Python
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t result(PyObject_CallMethod(self.o, (char *)S_ON_GETTEXT, "i", node));
  PyW_ShowCbErr(S_ON_GETTEXT);
  if ( result == NULL )
    return false;

  bgcolor_t cl = bg_color == NULL ? DEFCOLOR : *bg_color;
  const char *s;

  // User returned a string?
  if ( IDAPyStr_Check(result.o) )
  {
    s = IDAPyBytes_AsString(result.o);
    if ( s == NULL )
      s = "";
    c = node_cache.add(node, s, cl);
  }
  // User returned a sequence of text and bgcolor
  else if ( PySequence_Check(result.o) && PySequence_Size(result.o) == 2 )
  {
    newref_t py_str(PySequence_GetItem(result.o, 0));
    newref_t py_color(PySequence_GetItem(result.o, 1));

    if ( py_str == NULL || !IDAPyStr_Check(py_str.o) || (s = IDAPyBytes_AsString(py_str.o)) == NULL )
      s = "";
    if ( py_color != NULL && PyNumber_Check(py_color.o) )
      cl = bgcolor_t(PyLong_AsUnsignedLong(py_color.o));

    c = node_cache.add(node, s, cl);
  }

  *str = c->text.c_str();
  if ( bg_color != NULL )
    *bg_color = c->bgcolor;

  return true;
}

//-------------------------------------------------------------------------
int py_graph_t::on_hint(char **hint, int node)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t result(PyObject_CallMethod(self.o, (char *)S_ON_HINT, "i", node));
  PyW_ShowCbErr(S_ON_HINT);
  return _on_hint_epilog(hint, result);
}

//-------------------------------------------------------------------------
int py_graph_t::on_edge_hint(char **hint, int src, int dest)
{
  PYW_GIL_CHECK_LOCKED_SCOPE();
  newref_t result(PyObject_CallMethod(self.o, (char *)S_ON_EDGE_HINT, "ii", src, dest));
  PyW_ShowCbErr(S_ON_EDGE_HINT);
  return _on_hint_epilog(hint, result);
}

//-------------------------------------------------------------------------
int py_graph_t::_on_hint_epilog(char **hint, ref_t result)
{
  // 'hint' must be allocated by qalloc() or qstrdup()
  // out: 0-use default hint, 1-use proposed hint
  bool ok = result != NULL && IDAPyStr_Check(result.o);
  if ( ok )
    *hint = qstrdup(IDAPyBytes_AsString(result.o));
  return ok;
}

//-------------------------------------------------------------------------
ssize_t py_graph_t::gr_callback(int code, va_list va)
{
  int ret;
  switch ( code )
  {
    //
    case grcode_user_text:
      {
        mutable_graph_t *g  = va_arg(va, mutable_graph_t *);
        int node            = va_arg(va, int);
        const char **result = va_arg(va, const char **);
        bgcolor_t *bgcolor  = va_arg(va, bgcolor_t *);
        ret = on_user_text(g, node, result, bgcolor);
        break;
      }
      //
    case grcode_destroyed:
      on_graph_destroyed(va_arg(va, mutable_graph_t *));
      ret = 0;
      break;

      //
    case grcode_clicked:
      if ( has_callback(GRCODE_HAVE_CLICKED) )
      {
        graph_viewer_t *view     = va_arg(va, graph_viewer_t *);
        selection_item_t *item = va_arg(va, selection_item_t *);
        graph_item_t *gitem    = va_arg(va, graph_item_t *);
        ret = on_clicked(view, item, gitem);
      }
      else
      {
        // Ignore the click
        ret = 1;
      }
      break;
      //
    case grcode_dblclicked:
      if ( has_callback(GRCODE_HAVE_DBL_CLICKED) )
      {
        graph_viewer_t *view     = va_arg(va, graph_viewer_t *);
        selection_item_t *item = va_arg(va, selection_item_t *);
        ret = on_dblclicked(view, item);
      }
      else
        ret = 0; // We don't want to ignore the double click, but rather
                 // fallback to the default behavior (e.g., double-clicking
                 // on an edge will to jump to the node on the other side
                 // of that edge.)
      break;
      //
    case grcode_gotfocus:
      if ( has_callback(GRCODE_HAVE_GOTFOCUS) )
        on_gotfocus(va_arg(va, graph_viewer_t *));

      ret = 0;
      break;
      //
    case grcode_lostfocus:
      if ( has_callback(GRCODE_HAVE_LOSTFOCUS) )
        on_lostfocus(va_arg(va, graph_viewer_t *));

      ret = 0;
      break;
      //
    case grcode_user_refresh:
      on_user_refresh(va_arg(va, mutable_graph_t *));

      ret = 1;
      break;
      //
    case grcode_user_hint:
      {
        mutable_graph_t *g = va_arg(va, mutable_graph_t *);
        int node = va_arg(va, int);
        int src = va_arg(va, int);
        int dest = va_arg(va, int);
        char **hint = va_arg(va, char **);
        if ( node == -1 && has_callback(GRCODE_HAVE_EDGE_HINT) )
          ret = on_edge_hint(hint, src, dest);
        else if ( node >= 0 && has_callback(GRCODE_HAVE_HINT) )
          ret = on_hint(hint, node);
        else
          ret = 0;
      }
      break;
      //
    case grcode_changed_current:
      if ( has_callback(GRCODE_HAVE_CHANGED_CURRENT) )
      {
        graph_viewer_t *view = va_arg(va, graph_viewer_t *);
        int cur_node = va_arg(va, int);
        ret = on_changed_current(view, cur_node);
      }
      else
        ret = 0; // allow selection change
      break;
      //
    case grcode_creating_group:      // a group is being created
      if ( has_callback(GRCODE_HAVE_CREATING_GROUP) )
      {
        mutable_graph_t *g = va_arg(va, mutable_graph_t*);
        intvec_t *nodes = va_arg(va, intvec_t*);
        ret = on_creating_group(g, nodes);
      }
      else
      {
        ret = 0; // Ok to create
      }
      break;
      //
    case grcode_deleting_group:      // a group is being deleted
      if ( has_callback(GRCODE_HAVE_DELETING_GROUP) )
      {
        mutable_graph_t *g = va_arg(va, mutable_graph_t*);
        int old_group = va_arg(va, int);
        ret = on_deleting_group(g, old_group);
      }
      else
      {
        ret = 0; // Ok to delete
      }
      break;
      //
    case grcode_group_visibility:    // a group is being collapsed/uncollapsed
      if ( has_callback(GRCODE_HAVE_GROUP_VISIBILITY) )
      {
        mutable_graph_t *g = va_arg(va, mutable_graph_t*);
        int group = va_arg(va, int);
        bool expand = bool(va_arg(va, int));
        ret = on_group_visibility(g, group, expand);
      }
      else
      {
        ret = 0; // Ok.
      }
      break;
      //
    default:
      ret = 0;
      break;
  }
  //grcode_changed_graph,       // new graph has been set
  //grcode_user_size,           // calculate node size for user-defined graph
  //grcode_user_title,          // render node title of a user-defined graph
  //grcode_user_draw,           // render node of a user-defined graph
  return ret;
}

//-------------------------------------------------------------------------
bool pyg_show(PyObject *self)
{
  return py_graph_t::Show(self) != NULL;
}

void pyg_close(PyObject *self)
{
  py_graph_t *pyg = py_graph_t::Close(self);
  if ( pyg != NULL )
    delete pyg;
}

void pyg_select_node(PyObject *self, int nid)
{
  py_graph_t::SelectNode(self, nid);
}
//</code(py_graph)>
%}

%inline %{
//<inline(py_graph)>
void pyg_close(PyObject *self);
void pyg_select_node(PyObject *self, int nid);
bool pyg_show(PyObject *self);
//</inline(py_graph)>
%}

%pythoncode %{
#<pycode(py_graph)>
import ida_idaapi
import ida_kernwin
try:
    if _BC695:
        from ida_kernwin import BC695_control_cmd
except:
    pass # BC695 not defined at compile-time

class GraphViewer(ida_kernwin.CustomIDAMemo):
    class UI_Hooks_Trampoline(ida_kernwin.UI_Hooks):
        def __init__(self, v):
            ida_kernwin.UI_Hooks.__init__(self)
            self.hook()
            import weakref
            self.v = weakref.ref(v)

        def populating_widget_popup(self, form, popup_handle):
            my_form = self.v().GetWidget()
            if form == my_form:
                self.v().OnPopup(my_form, popup_handle)

    """This class wraps the user graphing facility provided by the graph.hpp file"""
    def __init__(self, title, close_open = False):
        """
        Constructs the GraphView object.
        Please do not remove or rename the private fields

        @param title: The title of the graph window
        @param close_open: Should it attempt to close an existing graph (with same title) before creating this graph?
        """
        self._title = title
        self._nodes = []
        self._edges = []
        self._close_open = close_open
        ida_kernwin.CustomIDAMemo.__init__(self)
        self.ui_hooks_trampoline = self.UI_Hooks_Trampoline(self)

    def AddNode(self, obj):
        """Creates a node associated with the given object and returns the node id"""
        id = len(self._nodes)
        self._nodes.append(obj)
        return id

    def AddEdge(self, src_node, dest_node):
        """Creates an edge between two given node ids"""
        assert src_node < len(self._nodes), "Source node %d is out of bounds" % src_node
        assert dest_node < len(self._nodes), "Destination node %d is out of bounds" % dest_node
        self._edges.append( (src_node, dest_node) )

    def Clear(self):
        """Clears all the nodes and edges"""
        self._nodes = []
        self._edges = []

    def OnPopup(self, form, popup_handle):
        pass

    def __iter__(self):
        return (self._nodes[index] for index in xrange(0, len(self._nodes)))


    def __getitem__(self, idx):
        """Returns a reference to the object associated with this node id"""
        if idx >= len(self._nodes):
            raise KeyError
        else:
            return self._nodes[idx]

    def Count(self):
        """Returns the node count"""
        return len(self._nodes)

    def Close(self):
        """
        Closes the graph.
        It is possible to call Show() again (which will recreate the graph)
        """
        _ida_graph.pyg_close(self)

    def Show(self):
        """
        Shows an existing graph or creates a new one

        @return: Boolean
        """
        if self._close_open:
            import ida_kernwin
            frm = ida_kernwin.find_widget(self._title)
            if frm:
                ida_kernwin.close_widget(frm, 0)
        return _ida_graph.pyg_show(self)

    def Select(self, node_id):
        """Selects a node on the graph"""
        _ida_graph.pyg_select_node(self, node_id)

    def OnRefresh(self):
        """
        Event called when the graph is refreshed or first created.
        From this event you are supposed to create nodes and edges.
        This callback is mandatory.

        @note: ***It is important to clear previous nodes before adding nodes.***
        @return: Returning True tells the graph viewer to use the items. Otherwise old items will be used.
        """
        self.Clear()

        return True

    def AddCommand(self, title, hotkey):
        return BC695_control_cmd.add_to_control(
            self,
            title,
            ida_kernwin.CHOOSER_POPUP_MENU, # KLUDGE
            -1, # menu index
            -1, # icon
            None, # emb
            hotkey,
            is_chooser=False)

    def OnPopup(self, widget, popup_handle):
        BC695_control_cmd.populate_popup(self, widget, popup_handle)

    def OnCommand(self, cmd_id):
        return 0


#<pydoc>
#    def OnGetText(self, node_id):
#        """
#        Triggered when the graph viewer wants the text and color for a given node.
#        This callback is triggered one time for a given node (the value will be cached and used later without calling Python).
#        When you call refresh then again this callback will be called for each node.
#
#        This callback is mandatory.
#
#        @return: Return a string to describe the node text or return a tuple (node_text, node_color) to describe both text and color
#        """
#        return str(self[node_id])
#
#    def OnActivate(self):
#        """
#        Triggered when the graph window gets the focus
#        @return: None
#        """
#        print "Activated...."
#
#    def OnDeactivate(self):
#        """Triggered when the graph window loses the focus
#        @return: None
#        """
#        print "Deactivated...."
#
#    def OnSelect(self, node_id):
#        """
#        Triggered when a node is being selected
#        @return: Return True to allow the node to be selected or False to disallow node selection change
#        """
#        # allow selection change
#        return True
#
#    def OnHint(self, node_id):
#        """
#        Triggered when the graph viewer wants to retrieve hint text associated with a given node
#
#        @return: None if no hint is avail or a string designating the hint
#        """
#        return "hint for " + str(node_id)
#
#    def OnEdgeHint(self, src, dst):
#        """
#        Triggered when the graph viewer wants to retrieve hint text associated with a edge
#
#        @return: None if no hint is avail or a string designating the hint
#        """
#        return "hint for edge %d -> %d" % (src, dst)
#
#    def OnClose(self):
#        """Triggered when the graph viewer window is being closed
#        @return: None
#        """
#        print "Closing......."
#
#    def OnClick(self, node_id):
#        """
#        Triggered when a node is clicked
#        @return: False to ignore the click and True otherwise
#        """
#        print "clicked on", self[node_id]
#        return True
#
#    def OnDblClick(self, node_id):
#        """
#        Triggerd when a node is double-clicked.
#        @return: False to ignore the click and True otherwise
#        """
#        print "dblclicked on", self[node_id]
#        return True
#</pydoc>
#</pycode(py_graph)>
%}
%pythoncode %{
if _BC695:
    clr_node_info2=clr_node_info
    del_node_info2=del_node_info
    get_node_info2=get_node_info
    set_node_info2=set_node_info
    GraphViewer.GetTForm = GraphViewer.GetWidget

%}