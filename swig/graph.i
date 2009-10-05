%{
//<code(py_graph)>
#ifndef __PY_IDA_GRAPH__
#define __PY_IDA_GRAPH__

#define GR_HAVE_USER_HINT         0x00000001
#define GR_HAVE_CLICKED           0x00000002
#define GR_HAVE_DBL_CLICKED       0x00000004
#define GR_HAVE_GOTFOCUS          0x00000008
#define GR_HAVE_LOSTFOCUS         0x00000010
#define GR_HAVE_CHANGED_CURRENT   0x00000020
#define GR_HAVE_CLOSE             0x00000040
#define GR_HAVE_COMMAND           0x00000080
#define S_ON_COMMAND              "OnCommand"
#define S_ON_REFRESH              "OnRefresh"
#define S_ON_HINT                 "OnHint"
#define S_ON_GETTEXT              "OnGetText"
#define S_ON_CLOSE                "OnClose"
#define S_ON_CLICK                "OnClick"
#define S_ON_DBL_CLICK            "OnDblClick"
#define S_ON_ACTIVATE             "OnActivate"
#define S_ON_DEACTIVATE           "OnDeactivate"
#define S_ON_SELECT               "OnSelect"
#define S_M_EDGES                 "_edges"
#define S_M_NODES                 "_nodes"
#define S_M_THIS                  "_this"
#define S_M_TITLE                 "_title"

#include <map>

class py_graph_t
{
private:
  struct nodetext_cache_t
  {
    qstring text;
    bgcolor_t bgcolor;
    nodetext_cache_t(const nodetext_cache_t &rhs): text(rhs.text), bgcolor(rhs.bgcolor) { }
    nodetext_cache_t(const char *t, bgcolor_t c): text(t), bgcolor(c) { }
    nodetext_cache_t() { }
  };
  class nodetext_cache_map_t: public std::map<int, nodetext_cache_t>
  {
  public:
    nodetext_cache_t *get(int node_id)
    {
      iterator it = find(node_id);
      if (it == end())
        return NULL;
      return &it->second;
    }
    nodetext_cache_t *add(const int node_id, const char *text, bgcolor_t bgcolor = DEFCOLOR)
    {
      return &(insert(std::make_pair(node_id,  nodetext_cache_t(text, bgcolor))).first->second);
    }
  };

  class tform_pygraph_map_t: public std::map<TForm *, py_graph_t *>
  {
  public:
    py_graph_t *get(TForm *form)
    {
      iterator it = find(form);
      return it == end() ? NULL : it->second;
    }
    void add(TForm *form, py_graph_t *py)
    {
      (*this)[form] = py;
    }
  };
  class cmdid_map_t: public std::map<Py_ssize_t, py_graph_t *>
  {
  private:
    Py_ssize_t uid;
  public:
    cmdid_map_t()
    {
      uid = 1; // we start by one and keep zero for error id
    }
    void add(py_graph_t *pyg)
    {
      (*this)[uid] = pyg;
      ++uid;
    }
    const Py_ssize_t id() const { return uid; }
    void clear(py_graph_t *pyg)
    {
      iterator e = end();
      for (iterator it=begin();it!=end();)
      {
        if (it->second == pyg)
        {
          iterator temp = it++;
          erase(temp);
        }
        else
          ++it;
      }
    }
    py_graph_t *get(Py_ssize_t id)
    {
      iterator it = find(id);
      return it == end() ? NULL : it->second;
    }
  };

  static tform_pygraph_map_t tform_pyg;
  static cmdid_map_t cmdid_pyg;
  int cb_flags;
  TForm *form;
  graph_viewer_t *gv;
  bool refresh_needed;
  PyObject *self;
  nodetext_cache_map_t node_cache;

  // static callback
  static int idaapi s_callback(void *obj, int code, va_list va)
  {
    return ((py_graph_t *)obj)->gr_callback(code, va);
  }

  static bool idaapi s_menucb(void *ud)
  {
    Py_ssize_t id = (Py_ssize_t)ud;
    py_graph_t *_this = cmdid_pyg.get(id);
    if (_this != NULL)
      _this->on_command(id);
    return true;
  }

  void on_command(Py_ssize_t id)
  {
    // Check return value to OnRefresh() call
    PyObject *ret = PyObject_CallMethod(self, S_ON_COMMAND, "n", id);
    Py_XDECREF(ret);
  }

  // Refresh user-defined graph node number and edges
  // It calls Python method and expects that the user already filled
  // the nodes and edges. The nodes and edges are retrieved and passed to IDA
  void on_user_refresh(mutable_graph_t *g)
  {
    if (!refresh_needed)
      return;

    // Check return value to OnRefresh() call
    PyObject *ret = PyObject_CallMethod(self, S_ON_REFRESH, NULL);
    if (ret == NULL || !PyBool_Check(ret) || ret != Py_True)
    {
      Py_XDECREF(ret);
      return;
    }

    // Refer to the nodes
    PyObject *nodes = PyObject_TryGetAttrString(self, S_M_NODES);
    if (ret == NULL || !PyList_Check(nodes))
    {
      Py_XDECREF(nodes);
      return;
    }

    // Refer to the edges
    PyObject *edges = PyObject_TryGetAttrString(self, S_M_EDGES);
    if (ret == NULL || !PyList_Check(nodes))
    {
      Py_DECREF(nodes);
      Py_XDECREF(edges);
      return;
    }

    // Resize the nodes
    int max_nodes = abs(int(PyList_Size(nodes)));
    g->clear();
    g->resize(max_nodes);

    // Mark that we refreshed already
    refresh_needed = false;

    // Clear cached nodes
    node_cache.clear();

    // Get the edges
    for (int i=(int)PyList_Size(edges)-1;i>=0;i--)
    {
      // Each list item is a sequence (id1, id2)
      PyObject *item = PyList_GetItem(edges, i);
      if (!PySequence_Check(item))
        continue;

      // Get and validate each of the two elements in the sequence
      int edge_ids[2];
      int j;
      for (j=0;j<qnumber(edge_ids);j++)
      {
        PyObject *id = PySequence_GetItem(item, j);
        if (id == NULL || !PyInt_Check(id))
        {
          Py_XDECREF(id);
          break;
        }
        int v = int(PyInt_AS_LONG(id));
        Py_DECREF(id);
        if (v > max_nodes)
          break;
        edge_ids[j] = v;
      }
      // Incomplete?
      if (j != qnumber(edge_ids))
        break;
      // Add the edge
      g->add_edge(edge_ids[0], edge_ids[1], NULL);
    }
    Py_DECREF(nodes);
    Py_DECREF(edges);
  }

  // Retrieves the text for user-defined graph node
  // It expects either a string or a tuple (string, bgcolor)
  bool on_user_text(mutable_graph_t * /*g*/, int node, const char **str, bgcolor_t *bg_color)
  {
    // If already cached then return the value
    nodetext_cache_t *c = node_cache.get(node);
    if (c != NULL)
    {
      *str = c->text.c_str();
      if (bg_color != NULL)
        *bg_color = c->bgcolor;
      return true;
    }

    // Not cached, call Python
    PyObject *result = PyObject_CallMethod(self, S_ON_GETTEXT, "l", node);
    if (result == NULL)
      return false;

    bgcolor_t cl = bg_color == NULL ? DEFCOLOR : *bg_color;
    const char *s;

    // User returned a string?
    if (PyString_Check(result))
    {
      s = PyString_AsString(result);
      if (s == NULL)
        s = "";
      c = node_cache.add(node, s, cl);
    }
    // User returned a sequence of text and bgcolor
    else if (PySequence_Check(result) && PySequence_Size(result) == 2)
    {
      PyObject *py_str   = PySequence_GetItem(result, 0);
      PyObject *py_color = PySequence_GetItem(result, 1);

      if (py_str == NULL || !PyString_Check(py_str) || (s = PyString_AsString(py_str)) == NULL)
        s = "";
      if (py_color != NULL && PyNumber_Check(py_color))
        cl = bgcolor_t(PyLong_AsUnsignedLong(py_color));

      c = node_cache.add(node, s, cl);

      Py_XDECREF(py_str);
      Py_XDECREF(py_color);
    }
    Py_DECREF(result);

    *str = c->text.c_str();
    if (bg_color != NULL)
      *bg_color = c->bgcolor;
    return true;
  }

  // Retrieves the hint for the user-defined graph
  // Calls Python and expects a string or None
  int on_user_hint(mutable_graph_t *, int mousenode, int /*mouseedge_src*/, int /*mouseedge_dst*/, char **hint)
  {
    // 'hint' must be allocated by qalloc() or qstrdup()
    // out: 0-use default hint, 1-use proposed hint

    // We dispatch hints over nodes only
    if (mousenode == -1)
      return 0;

    PyObject *result = PyObject_CallMethod(self, S_ON_HINT, "l", mousenode);
    bool ok = result != NULL && PyString_Check(result);
    if (!ok)
    {
      Py_XDECREF(result);
      return 0;
    }
    *hint = qstrdup(PyString_AsString(result));
    Py_DECREF(result);
    return 1; // use our hint
  }

  // graph is being destroyed
  void on_destroy(mutable_graph_t * /*g*/ = NULL)
  {
    if (self != NULL)
    {
      if (cb_flags & GR_HAVE_CLOSE)
      {
        PyObject *result = PyObject_CallMethod(self, S_ON_CLOSE, NULL);
        Py_XDECREF(result);
      }
      unbind();
    }
    // Remove the TForm from list
    if (form != NULL)
      tform_pyg.erase(form);
    // remove all associated commands from the list
    cmdid_pyg.clear(this);
    // Delete this instance
    delete this;
  }

  // graph is being clicked
  int on_clicked(graph_viewer_t * /*gv*/, selection_item_t * /*item1*/, graph_item_t *item2)
  {
    // in:  graph_viewer_t *gv
    //      selection_item_t *current_item1
    //      graph_item_t *current_item2
    // out: 0-ok, 1-ignore click
    // this callback allows you to ignore some clicks.
    // it occurs too early, internal graph variables are not updated yet
    // current_item1, current_item2 point to the same thing
    // item2 has more information.
    // see also: kernwin.hpp, custom_viewer_click_t
    if (item2->n == -1)
      return 1;

    PyObject *result = PyObject_CallMethod(self, S_ON_CLICK, "l", item2->n);
    if (result == NULL || !PyBool_Check(result) || result != Py_True)
    {
      Py_XDECREF(result);
      return 1;
    }

    Py_DECREF(result);

    return 0;
  }
  // a graph node has been double clicked
  int on_dblclicked(graph_viewer_t * /*gv*/, selection_item_t *item)
  {
    // in:  graph_viewer_t *gv
    //      selection_item_t *current_item
    // out: 0-ok, 1-ignore click
    //graph_viewer_t *v   = va_arg(va, graph_viewer_t *);
    //selection_item_t *s = va_arg(va, selection_item_t *);
    if (item == NULL || !item->is_node)
      return 1;
    PyObject *result = PyObject_CallMethod(self, S_ON_DBL_CLICK, "l", item->node);
    if (result == NULL || !PyBool_Check(result) || result != Py_True)
    {
      Py_XDECREF(result);
      return 1;
    }
    Py_DECREF(result);
    return 0;
  }

  // a graph viewer got focus
  void on_gotfocus(graph_viewer_t * /*gv*/)
  {
    PyObject *result = PyObject_CallMethod(self, S_ON_ACTIVATE, NULL);
    Py_XDECREF(result);
  }

  // a graph viewer lost focus
  void on_lostfocus(graph_viewer_t *gv)
  {
    PyObject *result = PyObject_CallMethod(self, S_ON_DEACTIVATE, NULL);
    Py_XDECREF(result);
  }

  // a new graph node became the current node
  int on_changed_current(graph_viewer_t * /*gv*/, int curnode)
  {
    // in:  graph_viewer_t *gv
    //      int curnode
    // out: 0-ok, 1-forbid to change the current node
    //graph_viewer_t *v = va_arg(va, graph_viewer_t *);
    //int curnode       = va_argi(va, int);
    //msg("%x: current node becomes %d\n", v, curnode);
    if (curnode < 0)
      return 0;
    PyObject *result = PyObject_CallMethod(self, S_ON_SELECT, "l", curnode);
    bool allow = (result != NULL && PyBool_Check(result) && result == Py_True);
    Py_XDECREF(result);
    return allow ? 0 : 1;
  }

  int gr_callback(int code, va_list va)
  {
    int ret;
    switch (code)
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
      on_destroy(va_arg(va, mutable_graph_t *));
      ret = 0;
      break;
    //
    case grcode_clicked:
      if (cb_flags & GR_HAVE_CLICKED)
      {
        graph_viewer_t *gv     = va_arg(va, graph_viewer_t *);
        selection_item_t *item = va_arg(va, selection_item_t *);
        graph_item_t    *gitem = va_arg(va, graph_item_t *);
        ret = on_clicked(gv, item, gitem);
      }
      else
        ret = 1; // ignore click
      break;
    //
    case grcode_dblclicked:
      if (cb_flags & GR_HAVE_DBL_CLICKED)
      {
        graph_viewer_t *gv     = va_arg(va, graph_viewer_t *);
        selection_item_t *item = va_arg(va, selection_item_t *);
        ret = on_dblclicked(gv, item);
      }
      else
        ret = 1; // ignore
      break;
    //
    case grcode_gotfocus:
      if (cb_flags & GR_HAVE_GOTFOCUS)
        on_gotfocus(va_arg(va, graph_viewer_t *));
      ret = 0;
      break;
    //
    case grcode_lostfocus:
      if (cb_flags & GR_HAVE_GOTFOCUS)
        on_lostfocus(va_arg(va, graph_viewer_t *));
      ret = 0;
      break;
    case grcode_user_refresh:
      on_user_refresh(va_arg(va, mutable_graph_t *));
      ret = 1;
      break;
    case grcode_user_hint:
      if (cb_flags & GR_HAVE_USER_HINT)
      {
        mutable_graph_t *g = va_arg(va, mutable_graph_t *);
        int mousenode      = va_arg(va, int);
        int mouseedge_src  = va_arg(va, int);
        int mouseedge_dest = va_arg(va, int);
        char **hint        = va_arg(va, char **);
        ret = on_user_hint(g, mousenode, mouseedge_src, mouseedge_dest, hint);
      }
      else
      {
        ret = 0;
      }
      break;
    case grcode_changed_current:
      if (cb_flags & GR_HAVE_CHANGED_CURRENT)
      {
        graph_viewer_t *gv = va_arg(va, graph_viewer_t *);
        int       cur_node = va_arg(va, int);
        ret = on_changed_current(gv, cur_node);
      }
      else
        ret = 0; // allow selection change
      break;
    default:
      ret = 0;
      break;
    }
    //grcode_changed_graph,       // new graph has been set
    //grcode_creating_group,      // a group is being created
    //grcode_deleting_group,      // a group is being deleted
    //grcode_group_visibility,    // a group is being collapsed/uncollapsed
    //grcode_user_size,           // calculate node size for user-defined graph
    //grcode_user_title,          // render node title of a user-defined graph
    //grcode_user_draw,           // render node of a user-defined graph
    return ret;
  }
  static PyObject *PyObject_TryGetAttrString(PyObject *object, const char *attr)
  {
    if (!PyObject_HasAttrString(object, attr))
      return NULL;
    return PyObject_GetAttrString(object, attr);
  }

  void unbind()
  {
    if (self == NULL)
      return;

    // Unbind this object from the python object
    PyObject_SetAttrString(self, S_M_THIS, PyCObject_FromVoidPtr(NULL, NULL));
    Py_XDECREF(self);
    self = NULL;
  }

  void show()
  {
    open_tform(form, FORM_MDI|FORM_TAB|FORM_MENU);
  }

  static py_graph_t *extract_this(PyObject *self)
  {
    // Try to extract "this" from the python object
    PyObject *py_this = PyObject_TryGetAttrString(self, S_M_THIS);
    if (py_this == NULL || !PyCObject_Check(py_this))
    {
      Py_XDECREF(py_this);
      return NULL;
    }
    py_graph_t *ret = (py_graph_t *) PyCObject_AsVoidPtr(py_this);
    Py_DECREF(py_this);
    return ret;
  }

  void jump_to_node(int nid)
  {
    viewer_center_on(gv, nid);
    int x, y;

    // will return a place only when a node was previously selected
    place_t *old_pl = get_custom_viewer_place(gv, false, &x, &y);
    if ( old_pl != NULL )
    {
#ifdef __BORLANDC__
      user_graph_place_t *new_pl = (user_graph_place_t *) old_pl->clone();
#else
      // although this works, it may not work in the future
      user_graph_place_t *new_pl = (user_graph_place_t *) qalloc(sizeof(user_graph_place_t));
      memcpy(new_pl, old_pl, sizeof(user_graph_place_t));
#endif
      new_pl->node = nid;
      jumpto(gv, new_pl, x, y);
#ifdef __BORLANDC__
      delete new_pl;
#else
      qfree(new_pl);
#endif
    }
  }

  void refresh()
  {
    refresh_needed = true;
    refresh_viewer(gv);
  }

  static bool extract_title(PyObject *self, qstring *title)
  {
    PyObject *py_title = PyObject_TryGetAttrString(self, S_M_TITLE);
    if ( py_title == NULL )
      return false;
    *title = PyString_AsString(py_title);
    Py_DECREF(py_title);
    return true;
  }

  int create(PyObject *self, const char *title)
  {
    // check what callbacks we have
    static const struct
    {
      const char *name;
      int have;
    } callbacks[] =
    {
      {S_ON_REFRESH,       0}, // 0 = mandatory callback
      {S_ON_GETTEXT,       0},
      {S_M_EDGES,         -1}, // -1 = mandatory attributes
      {S_M_NODES,         -1},
      {S_ON_HINT,          GR_HAVE_USER_HINT},
      {S_ON_CLICK,         GR_HAVE_CLICKED},
      {S_ON_DBL_CLICK,     GR_HAVE_DBL_CLICKED},
      {S_ON_CLOSE,         GR_HAVE_CLOSE},
      {S_ON_COMMAND,       GR_HAVE_COMMAND},
      {S_ON_SELECT,        GR_HAVE_CHANGED_CURRENT},
      {S_ON_ACTIVATE,      GR_HAVE_GOTFOCUS},
      {S_ON_DEACTIVATE,    GR_HAVE_LOSTFOCUS}
    };
    cb_flags = 0;
    for (int i=0;i<qnumber(callbacks);i++)
    {
      PyObject *attr = PyObject_TryGetAttrString(self, callbacks[i].name);
      int have = callbacks[i].have;
      // Mandatory fields not present?
      if ((attr == NULL && have <= 0)
        // Mandatory callback fields present but not callable?
        || (attr != NULL && have >= 0 && PyCallable_Check(attr) == 0))
      {
        Py_XDECREF(attr);
        return -1;
      }
      if (have > 0 && attr != NULL)
        cb_flags |= have;
      Py_XDECREF(attr);
    }

    // Bind py_graph_t to python object
    this->self = self;
    Py_INCREF(self);
    PyObject_SetAttrString(self, S_M_THIS, PyCObject_FromVoidPtr(this, NULL));

    // Create form
    HWND hwnd = NULL;
    form = create_tform(title, &hwnd);

    // Link "form" and "py_graph"
    tform_pyg.add(form, this);

    if (hwnd != NULL)
    {
      // get a unique graph id
      netnode id;
      id.create();
      gv = create_graph_viewer(form, id, s_callback, this, 0);
      open_tform(form, FORM_MDI|FORM_TAB|FORM_MENU);
      if (gv != NULL)
        viewer_fit_window(gv);
    }
    else
    {
      show();
    }
    viewer_fit_window(gv);
    return 0;
  }

  Py_ssize_t add_command(const char *title, const char *hotkey)
  {
    if ( (cb_flags & GR_HAVE_COMMAND) == 0 || gv == NULL)
      return 0;
    Py_ssize_t cmd_id = cmdid_pyg.id();
    bool ok = viewer_add_menu_item(gv, title, s_menucb, (void *)cmd_id, hotkey, 0);
    if (!ok)
      return 0;
    cmdid_pyg.add(this);
    return cmd_id;
  }

  public:
    py_graph_t()
    {
      form = NULL;
      gv = NULL;
      refresh_needed = true;
      self = NULL;
    }

    static void SelectNode(PyObject *self, int nid)
    {
      py_graph_t *_this = extract_this(self);
      if (_this == NULL || _this->form == NULL)
        return;
      _this->jump_to_node(0);
    }

    static Py_ssize_t AddCommand(PyObject *self, const char *title, const char *hotkey)
    {
      py_graph_t *_this = extract_this(self);
      if (_this == NULL || _this->form == NULL)
        return 0;
      return _this->add_command(title, hotkey);
    }

    static void Close(PyObject *self)
    {
      py_graph_t *_this = extract_this(self);
      if (_this == NULL || _this->form == NULL)
        return;
      close_tform(_this->form, 0);
    }

    static void Refresh(PyObject *self)
    {
      py_graph_t *_this = extract_this(self);
      if (_this == NULL)
        return;
      _this->refresh();
    }

    static py_graph_t *Show(PyObject *self)
    {
      py_graph_t *ret = extract_this(self);
      if (ret == NULL)
      {
        qstring title;
        if (!extract_title(self, &title))
          return NULL;

        // Form already created? try to get associated py_graph instance
        // so that we reuse it
        ret = tform_pyg.get(find_tform(title.c_str()));

        // Instance not found? create a new one
        if (ret == NULL)
          ret = new py_graph_t();
        else
        {
          // unbind so we are rebound
          ret->unbind();
          ret->refresh_needed = true;
        }
        if (ret->create(self, title.c_str()) < 0)
        {
          delete ret;
          ret = NULL;
        }
      }
      else
      {
        ret->show();
      }
      return ret;
    }
};

py_graph_t::tform_pygraph_map_t py_graph_t::tform_pyg;
py_graph_t::cmdid_map_t         py_graph_t::cmdid_pyg;

bool pyg_show(PyObject *self)
{
  return py_graph_t::Show(self) != NULL;
}

void pyg_refresh(PyObject *self)
{
  py_graph_t::Refresh(self);
}

void pyg_close(PyObject *self)
{
  py_graph_t::Close(self);
}

Py_ssize_t pyg_add_command(PyObject *self, const char *title, const char *hotkey)
{
  return py_graph_t::AddCommand(self, title, hotkey);
}

void pyg_select_node(PyObject *self, int nid)
{
  py_graph_t::SelectNode(self, nid);
}

#undef GR_HAVE_USER_HINT
#undef GR_HAVE_CLICKED
#undef GR_HAVE_DBL_CLICKED
#undef GR_HAVE_GOTFOCUS
#undef GR_HAVE_LOSTFOCUS
#undef GR_HAVE_CHANGED_CURRENT
#undef GR_HAVE_CLOSE
#undef GR_HAVE_COMMAND
#undef S_ON_COMMAND
#undef S_ON_REFRESH
#undef S_ON_HINT
#undef S_ON_GETTEXT
#undef S_ON_CLOSE
#undef S_ON_CLICK
#undef S_ON_DBL_CLICK
#undef S_ON_ACTIVATE
#undef S_ON_DEACTIVATE
#undef S_ON_SELECT
#undef S_M_EDGES
#undef S_M_NODES
#undef S_M_THIS
#undef S_M_TITLE

#endif
//</code(py_graph)>
%}

%pythoncode %{
#<pycode(py_graph)>
class GraphViewer:
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

    def AddNode(self, obj):
        """Creates a node associated with the given object and returns the node id"""
        id = len(self._nodes)
        self._nodes.append(obj)
        return id

    def AddEdge(self, src_node, dest_node):
        """Creates an edge between two given node ids"""
        self._edges.append( (src_node, dest_node) )

    def Clear(self):
        """Clears all the nodes and edges"""
        self._nodes = []
        self._edges = []

    def __getitem__(self, idx):
        """Returns a reference to the object associated with this node id"""
        if idx > len(self._nodes):
            raise StopIteration
        return self._nodes[idx]

    def Count(self):
        """Returns the node count"""
        return len(self._nodes)

    def Close(self):
        """
        Closes the graph.
        It is possible to call Show() again (which will recreate the graph)
        """
        _idaapi.pyg_close(self)

    def Refresh(self):
        """
        Refreshes the graph. This causes the OnRefresh() to be called
        """
        _idaapi.pyg_refresh(self)

    def Show(self):
        """
        Shows an existing graph or creates a new one

        @return: Boolean
        """
        if self._close_open:
            frm = _idaapi.find_tform(self._title)
            if frm:
                _idaapi.close_tform(frm, 0)
        return _idaapi.pyg_show(self)

    def Select(self, node_id):
        """Selects a node on the graph"""
        _idaapi.pyg_select_node(self, node_id)

    def AddCommand(self, title, hotkey):
        """
        Adds a menu command to the graph.
        Once a command is added, a command id is returned. The commands are handled inside the OnCommand() handler

        @return: 0 or the command id
        """
        return _idaapi.pyg_add_command(self, title, hotkey)

    def OnRefresh(self):
        """
        Event called when the graph is refreshed or first created.
        From this event you are supposed to create nodes and edges.
        @note: ***It is important to clear previous nodes before adding nodes.***
        @return: Returning true tells the graph viewer to use the items. Otherwise old items will be used.
        """
        self.Clear()

        return True

#    def OnActivate(self):
#        """Triggered when the graph window gets the focus"""
#        print "Activated...."

#    def OnDeactivate(self):
#        """Triggered when the graph window loses the focus"""
#        print "Deactivated...."

#    def OnSelect(self, node_id):
#        """
#        Triggered when a node is being selected
#        @return: Return True to allow the node to be selected or False to disallow node selection change
#        """
#        # allow selection change
#        return True

#    def OnGetText(self, node_id):
#        """
#        Triggered when the graph viewer wants the text and color for a given node.
#        This callback is triggered one time for a given node (the value will be cached and used later without calling Python).
#        When you call refresh then again this callback will be called for each node.
#
#        @return: Return a string to describe the node text or return a tuple (node_text, node_color) to describe both text and color
#        """
#        return str(self[node_id])

#    def OnHint(self, node_id):
#        """
#        Triggered when the graph viewer wants to retrieve hint text associated with a given node
#
#        @return: None if no hint is avail or a string designating the hint
#        """
#        return "hint for " + str(node_id)

#    def OnClose(self):
#        """Triggered when the graph viewer window is being closed"""
#        print "Closing......."

#    def OnClick(self, node_id):
#        """
#        Triggered when a node is clicked
#        @return: False to ignore the click and true otherwise
#        """
#        print "clicked on", self[node_id]
#        return True

#    def OnDblClick(self, node_id):
#        """
#        Triggerd when a node is double-clicked.
#        @note: check OnClick() event
#        """
#        print "dblclicked on", self[node_id]
#        return True

#    def OnCommand(self, cmd_id):
#        """
#        Triggered when a menu command is selected through the menu or its hotkey
#        """
#        print "command:", cmd_id
#</pycode(py_graph)>
%}

%inline %{
//<inline(py_graph)>
void pyg_refresh(PyObject *self);
void pyg_close(PyObject *self);

Py_ssize_t pyg_add_command(PyObject *self, const char *title, const char *hotkey);
void pyg_select_node(PyObject *self, int nid);
bool pyg_show(PyObject *self);
//</inline(py_graph)>
%}
