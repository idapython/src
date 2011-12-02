#include "py_custview.hpp"

//--------------------------------------------------------------------------
class my_custviewer: public customviewer_t
{
private:
  cvdata_simpleline_t data;
  size_t id_n;
  virtual bool on_popup_menu(size_t menu_id)
  {
    if ( menu_id == id_n )
      msg("popup menu N chosen!\n");
    return true;
  }
  virtual bool on_click(int shift)
  {
    msg("onclick; shift=%d\n", shift);
    return true;
  }
  virtual void on_close()
  {
    id_n = 0;
    msg("closed...\n");
  }
  virtual bool on_keydown(int key, int shift)
  {
    switch ( key )
    {
    case 'N':
      warning("The hotkey 'N' has been pressed");
      return true;
    case 'I':
      {
        int x, y;
        place_t *pl = get_place(false, &x, &y);
        if ( pl == NULL )
          return false;
        msg("x=%d y=%d\n", x, y);
        simpleline_t sl = *data.get_line(pl);
        sl.bgcolor = bgcolor_t(~uint32(sl.bgcolor));
        data.set_line(data.to_lineno(pl), sl);
        refresh_current();
        return true;
      }
    case 'A':
      {
        char buf[100];
        qsnprintf(buf, sizeof(buf), "This is line %d\n", data.count());
        data.add_line(buf);
        msg("Added one more line...\n");
        return true;
      }
    case 'S':
      {
        twinpos_t p1, p2;
        ::readsel2(_cv, &p1, &p2);
        size_t y1 = data.to_lineno(p1.at);
        size_t y2 = data.to_lineno(p2.at);
        int x1 = p1.x;
        int x2 = p2.x;
        msg("(x1=%d y1=%d) (x2=%d y2=%d)", x1, y1, x2, y2);
        return true;
      }
    case 'X':
      data.set_minmax();
      return true;
    case 'R':
      refresh();
      msg("refreshing!\n");
      return true;
    case IK_ESCAPE:
      close();
      return true;
    }
    return false;
  }
  virtual void on_curpos_changed()
  {
    qstring word;
    if ( get_current_word(false, word) )
      msg("Current word is: %s\n", word.c_str());
  }
  virtual bool on_hint(place_t *place, int *important_lines, qstring &hint)
  {
    simpleline_t *line = data.get_line(place);
    if ( line == NULL )
      return false;
    *important_lines = 1;
    hint = line->line;
    return true;
  }

public:
  void init_sample_lines()
  {
    strvec_t &lines = data.get_lines();
    static struct
    {
      const char *text;
      bgcolor_t color;
    } const sample_lines[] =
    {
      { "This is a sample text",                                         0xFFFFFF },
      { "It will be displayed in the custom view",                       0xFFC0C0 },
      { COLSTR("This line will be colored as erroneous", SCOLOR_ERROR),  0xC0FFC0 },
      { COLSTR("Every", SCOLOR_AUTOCMT) " "
      COLSTR("word", SCOLOR_DNAME) " "
      COLSTR("can", SCOLOR_IMPNAME) " "
      COLSTR("be", SCOLOR_NUMBER) " "
      COLSTR("colored!", SCOLOR_EXTRA),                                  0xC0C0FF },
      { "  No limit on the number of lines.",                            0xC0FFFF },
    };
    for ( int i=0; i<qnumber(sample_lines); i++ )
    {
      lines.push_back(simpleline_t("")); // add empty line
      lines.push_back(simpleline_t(sample_lines[i].text));
      lines.back().bgcolor = sample_lines[i].color;
    }
  }
  my_custviewer()
  {
    id_n = 0;
    init_sample_lines();
    data.set_minmax();
  }
  bool init(const char *title)
  {
    if ( id_n != 0 )
      return true;
    if ( !create(title, HAVE_HINT | HAVE_CLICK | HAVE_KEYDOWN | HAVE_CURPOS, &data) )
      return false;
    id_n = add_popup_menu("Do this", "N");
    return true;
  }
};

my_custviewer *g_cv;

//-------------------------------------------------------------------------
static PyObject *ex_pyscv_init(PyObject *self, PyObject *args)
{
  const char *title;
  PyObject *py_link;
  if ( !PyArg_ParseTuple(args, "Os", &py_link, &title) )
    return NULL;
  return pyscv_init(py_link, title);
}

static PyObject *ex_pyscv_add_line(PyObject *self, PyObject *args)
{
  PyObject *py_this, *py_sl;
  if ( !PyArg_ParseTuple(args, "OO", &py_this, &py_sl) )
    return NULL;
  return Py_BuildValue("i", pyscv_add_line(py_this, py_sl));
}

static PyObject *ex_pyscv_delete(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  if ( !PyArg_ParseTuple(args, "O", &py_this) )
    return NULL;
  return Py_BuildValue("i", pyscv_delete(py_this));
}

static PyObject *ex_pyscv_show(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  if ( !PyArg_ParseTuple(args, "O", &py_this) )
    return NULL;
  return Py_BuildValue("i", pyscv_show(py_this));
}

static PyObject *ex_pyscv_refresh(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  if ( !PyArg_ParseTuple(args, "O", &py_this) )
    return NULL;
  return Py_BuildValue("i", pyscv_refresh(py_this));
}

static PyObject *ex_pyscv_close(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  if ( !PyArg_ParseTuple(args, "O", &py_this) )
    return NULL;
  pyscv_close(py_this);
  Py_RETURN_NONE;
}

static PyObject *ex_pyscv_clear_popup_menu(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  if ( !PyArg_ParseTuple(args, "O", &py_this) )
    return NULL;
  pyscv_clear_popup_menu(py_this);
  Py_RETURN_NONE;
}

static PyObject *ex_pyscv_del_line(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  size_t nline;
  if ( !PyArg_ParseTuple(args, "O" PY_FMT64, &py_this, &nline) )
    return NULL;
  return Py_BuildValue("i", pyscv_del_line(py_this, nline));
}

static PyObject *ex_pyscv_get_pos(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  int mouse;
  if ( !PyArg_ParseTuple(args, "Oi", &py_this, &mouse) )
    return NULL;
  return pyscv_get_pos(py_this, mouse == 0 ? false : true);
}

static PyObject *ex_pyscv_refresh_current(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  int mouse;
  if ( !PyArg_ParseTuple(args, "Oi", &py_this, &mouse) )
    return NULL;
  return Py_BuildValue("i", pyscv_refresh_current(py_this));
}

static PyObject *ex_pyscv_get_current_line(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  int mouse, notags;
  if ( !PyArg_ParseTuple(args, "Oii", &py_this, &mouse, &notags) )
    return NULL;
  return pyscv_get_current_line(py_this, mouse == 0 ? false : true, notags == 0 ? false : true);
}

static PyObject *ex_pyscv_is_focused(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  if ( !PyArg_ParseTuple(args, "O", &py_this) )
    return NULL;
  return Py_BuildValue("i", pyscv_is_focused(py_this));
}

static PyObject *ex_pyscv_add_popup_menu(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  const char *title, *hotkey;
  if ( !PyArg_ParseTuple(args, "Oss", &py_this, &title, &hotkey) )
    return NULL;
  return Py_BuildValue("i", pyscv_add_popup_menu(py_this, title, hotkey));
}

static PyObject *ex_pyscv_get_line(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  size_t nline;
  if ( !PyArg_ParseTuple(args, "O" PY_FMT64, &py_this, &nline) )
    return NULL;
  return pyscv_get_line(py_this, nline);
}

static PyObject *ex_pyscv_jumpto(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  int x, y;
  size_t lineno;
  if ( !PyArg_ParseTuple(args, "O" PY_FMT64 "ii", &py_this, &lineno, &x, &y) )
    return NULL;
  return Py_BuildValue("i", pyscv_jumpto(py_this, lineno, x, y));
}

static PyObject *ex_pyscv_edit_line(PyObject *self, PyObject *args)
{
  PyObject *py_this, *py_sl;
  size_t lineno;
  if ( !PyArg_ParseTuple(args, "O" PY_FMT64 "O", &py_this, &lineno, &py_sl) )
    return NULL;
  return Py_BuildValue("i", pyscv_edit_line(py_this, lineno, py_sl));
}

static PyObject *ex_pyscv_insert_line(PyObject *self, PyObject *args)
{
  PyObject *py_this, *py_sl;
  size_t lineno;
  if ( !PyArg_ParseTuple(args, "O" PY_FMT64 "O", &py_this, &lineno, &py_sl) )
    return NULL;
  return Py_BuildValue("i", pyscv_insert_line(py_this, lineno, py_sl));
}

static PyObject *ex_pyscv_patch_line(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  size_t lineno, offs;
  int value;
  if ( !PyArg_ParseTuple(args, "O" PY_FMT64 PY_FMT64 "i", &py_this, &lineno, &offs, &value) )
    return NULL;
  return Py_BuildValue("i", pyscv_patch_line(py_this, lineno, offs, value));
}

static PyObject *ex_pyscv_count(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  if ( !PyArg_ParseTuple(args, "O", &py_this) )
    return NULL;
  return Py_BuildValue(PY_FMT64, pyscv_count(py_this));
}

static PyObject *ex_pyscv_get_selection(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  if ( !PyArg_ParseTuple(args, "O", &py_this) )
    return NULL;
  return pyscv_get_selection(py_this);
}

static PyObject *ex_pyscv_get_current_word(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  int mouse;
  if ( !PyArg_ParseTuple(args, "Oi", &py_this, &mouse) )
    return NULL;
  return pyscv_get_current_word(py_this, mouse != 0);
}

static PyObject *ex_pyscv_clear_lines(PyObject *self, PyObject *args)
{
  PyObject *py_this;
  if ( !PyArg_ParseTuple(args, "O", &py_this) )
    return NULL;
  return pyscv_clear_lines(py_this);
}

//-------------------------------------------------------------------------
static PyMethodDef py_methods_custview[] =
{
  {"pyscv_init",  ex_pyscv_init, METH_VARARGS, ""},
  {"pyscv_close",  ex_pyscv_close, METH_VARARGS, ""},
  {"pyscv_add_line",  ex_pyscv_add_line, METH_VARARGS, ""},
  {"pyscv_delete",  ex_pyscv_delete, METH_VARARGS, ""},
  {"pyscv_refresh",  ex_pyscv_refresh, METH_VARARGS, ""},
  {"pyscv_clear_lines", ex_pyscv_clear_lines, METH_VARARGS, ""},
  {"pyscv_show",  ex_pyscv_show, METH_VARARGS, ""},
  {"pyscv_clear_popup_menu", ex_pyscv_clear_popup_menu, METH_VARARGS, ""},
  {"pyscv_del_line", ex_pyscv_del_line, METH_VARARGS, ""},
  {"pyscv_get_pos", ex_pyscv_get_pos, METH_VARARGS, ""},
  {"pyscv_refresh_current", ex_pyscv_refresh_current, METH_VARARGS, ""},
  {"pyscv_get_current_line", ex_pyscv_get_current_line, METH_VARARGS, ""},
  {"pyscv_is_focused", ex_pyscv_is_focused, METH_VARARGS, ""},
  {"pyscv_add_popup_menu", ex_pyscv_add_popup_menu, METH_VARARGS, ""},
  {"pyscv_get_line", ex_pyscv_get_line, METH_VARARGS, ""},
  {"pyscv_jumpto", ex_pyscv_jumpto, METH_VARARGS, ""},
  {"pyscv_edit_line", ex_pyscv_edit_line, METH_VARARGS, ""},
  {"pyscv_insert_line", ex_pyscv_insert_line, METH_VARARGS, ""},
  {"pyscv_count", ex_pyscv_count, METH_VARARGS, ""},
  {"pyscv_patch_line", ex_pyscv_patch_line, METH_VARARGS, ""},
  {"pyscv_get_selection", ex_pyscv_get_selection, METH_VARARGS, ""},
  {"pyscv_get_current_word", ex_pyscv_get_current_word, METH_VARARGS, ""},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};
DRIVER_INIT_METHODS(custview);

#define DRIVER_RUN
void driver_run(int)
{
  if ( !g_cv->init("My sample viewer!") )
  {
    msg("Failed to create cv\n!");
    return;
  }
  g_cv->show();
}

#define DRIVER_INIT
int driver_init()
{
  g_cv = new my_custviewer();
  return PLUGIN_KEEP;
}

#define DRIVER_TERM
void driver_term()
{
  g_cv->close();
  delete g_cv;
}
