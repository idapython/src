#ifndef __PY_KERNWIN_ASKFORM__
#define __PY_KERNWIN_ASKFORM__

//<code(py_kernwin_askform)>
//</code(py_kernwin_askform)>

//---------------------------------------------------------------------------
//<inline(py_kernwin_askform)>
#define DECLARE_FORM_ACTIONS form_actions_t *fa = (form_actions_t *)p_fa;

#ifdef TESTABLE_BUILD
#include <features.hpp>
#endif
//---------------------------------------------------------------------------
static bool textctrl_info_t_assign(PyObject *self, PyObject *other)
{
  textctrl_info_t *lhs = textctrl_info_t_get_clink(self);
  textctrl_info_t *rhs = textctrl_info_t_get_clink(other);
  if ( lhs == nullptr || rhs == nullptr )
    return false;

  *lhs = *rhs;
  return true;
}

//-------------------------------------------------------------------------
static bool textctrl_info_t_set_text(PyObject *self, const char *s)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  if ( ti == nullptr )
    return false;
  ti->text = s;
  return true;
}

//-------------------------------------------------------------------------
static const char *textctrl_info_t_get_text(PyObject *self)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  return ti == nullptr ? "" : ti->text.c_str();
}

//-------------------------------------------------------------------------
static bool textctrl_info_t_set_flags(PyObject *self, unsigned int flags)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  if ( ti == nullptr )
    return false;
  ti->flags = flags;
  return true;
}

//-------------------------------------------------------------------------
static unsigned int textctrl_info_t_get_flags(PyObject *self)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  return ti == nullptr ? 0 : ti->flags;
}

//-------------------------------------------------------------------------
static bool textctrl_info_t_set_tabsize(PyObject *self, unsigned int tabsize)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  if ( ti == nullptr )
    return false;
  ti->tabsize = tabsize;
  return true;
}

//-------------------------------------------------------------------------
static unsigned int textctrl_info_t_get_tabsize(PyObject *self)
{
  textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(self);
  return ti == nullptr ? 0 : ti->tabsize;
}

//---------------------------------------------------------------------------
static bool formchgcbfa_enable_field(size_t p_fa, int fid, bool enable)
{
  DECLARE_FORM_ACTIONS;
  return fa->enable_field(fid, enable);
}

//---------------------------------------------------------------------------
static bool formchgcbfa_show_field(size_t p_fa, int fid, bool show)
{
  DECLARE_FORM_ACTIONS;
  return fa->show_field(fid, show);
}

//---------------------------------------------------------------------------
static bool formchgcbfa_move_field(
        size_t p_fa,
        int fid,
        int x,
        int y,
        int w,
        int h)
{
  DECLARE_FORM_ACTIONS;
  return fa->move_field(fid, x, y, w, h);
}

//---------------------------------------------------------------------------
static int formchgcbfa_get_focused_field(size_t p_fa)
{
  DECLARE_FORM_ACTIONS;
  return fa->get_focused_field();
}

//---------------------------------------------------------------------------
static bool formchgcbfa_set_focused_field(size_t p_fa, int fid)
{
  DECLARE_FORM_ACTIONS;
  return fa->set_focused_field(fid);
}

//---------------------------------------------------------------------------
static void formchgcbfa_refresh_field(size_t p_fa, int fid)
{
  DECLARE_FORM_ACTIONS;
  return fa->refresh_field(fid);
}

//---------------------------------------------------------------------------
static void formchgcbfa_close(size_t p_fa, int close_normally)
{
  DECLARE_FORM_ACTIONS;
  fa->close(close_normally);
}

//---------------------------------------------------------------------------
static PyObject *formchgcbfa_get_field_value(
        size_t p_fa,
        int fid,
        int ft,
        size_t sz)
{
  DECLARE_FORM_ACTIONS;
  PYW_GIL_CHECK_LOCKED_SCOPE();
  switch ( ft )
  {
    // dropdown list
    case 8:
      // Readonly? Then return the selected index
      if ( sz == 1 )
      {
        int sel_idx;
        if ( fa->get_combobox_value(fid, &sel_idx) )
          return PyLong_FromLong(sel_idx);
      }
      // Not readonly? Then return the qstring
      else
      {
        qstring val;
        if ( fa->get_combobox_value(fid, &val) )
          return PyUnicode_FromString(val.c_str());
      }
      break;

    // multilinetext - tuple representing textctrl_info_t
    case 7:
      {
        textctrl_info_t ti;
        if ( fa->get_text_value(fid, &ti) )
          return Py_BuildValue("(sII)", ti.text.c_str(), ti.flags, ti.tabsize);
        break;
      }
    // button - uint32
    case 4:
      {
        uval_t val;
        if ( fa->get_unsigned_value(fid, &val) )
          return PyLong_FromUnsignedLong(val);
        break;
      }
    // ushort
    case 2:
      {
        ushort val;
        if ( fa->_get_field_value(fid, &val) )
          return PyLong_FromUnsignedLong(val);
        break;
      }
    // string label
    case 1:
      {
        char val[MAXSTR];
        if ( fa->get_string_value(fid, val, sizeof(val)) )
          return PyUnicode_FromString(val);
        break;
      }
    // string input
    case 3:
      {
        qstring val;
        val.resize(sz + 1);
        if ( fa->get_string_value(fid, val.begin(), val.size()) )
          return PyUnicode_FromString(val.begin());
        break;
      }
    case 5:
      {
        sizevec_t selection;
        if ( fa->get_chooser_value(fid, &selection) )
        {
          ref_t l(PyW_SizeVecToPyList(selection));
          l.incref();
          return l.o;
        }
        break;
      }
    // Numeric control
    case 6:
      {
        union
        {
          sel_t sel;
          sval_t sval;
          uval_t uval;
          uint64 ull;
        } u;
        switch ( sz )
        {
          case 'S': // sel_t
            if ( fa->get_segment_value(fid, &u.sel) )
              return Py_BuildValue(PY_BV_SEL, bvsel_t(u.sel));
            break;
          // sval_t
          case 'n':
          case 'D':
          case 'O':
          case 'Y':
          case 'H':
            if ( fa->get_signed_value(fid, &u.sval) )
              return Py_BuildValue(PY_BV_SVAL, bvsval_t(u.sval));
            break;
          case 'L': // uint64
          case 'l': // int64
            if ( fa->_get_field_value(fid, &u.ull) )
              return Py_BuildValue("K", u.ull);
            break;
          case 'N':
          case 'M': // uval_t
            if ( fa->get_unsigned_value(fid, &u.uval) )
              return Py_BuildValue(PY_BV_UVAL, bvuval_t(u.uval));
            break;
          case '$': // ea_t
            if ( fa->get_ea_value(fid, &u.uval) )
              return Py_BuildValue(PY_BV_UVAL, bvuval_t(u.uval));
            break;
        }
        break;
      }
  }
  Py_RETURN_NONE;
}

//---------------------------------------------------------------------------
static bool formchgcbfa_set_field_value(
        size_t p_fa,
        int fid,
        int ft,
        PyObject *py_val)
{
  DECLARE_FORM_ACTIONS;
  PYW_GIL_CHECK_LOCKED_SCOPE();

  switch ( ft )
  {
    // dropdown list
    case 8:
      // Editable dropdown list
      if ( PyUnicode_Check(py_val) )
      {
        qstring val;
        PyUnicode_as_qstring(&val, py_val);
        return fa->set_combobox_value(fid, &val);
      }
      // Readonly dropdown list
      else
      {
        int sel_idx = PyLong_AsLong(py_val);
        return fa->set_combobox_value(fid, &sel_idx);
      }
      break;

    // multilinetext - textctrl_info_t
    case 7:
      {
        textctrl_info_t *ti = (textctrl_info_t *)pyobj_get_clink(py_val);
        return ti != nullptr && fa->set_text_value(fid, ti);
      }
    // button - uint32
    case 4:
      {
        uval_t val = PyLong_AsUnsignedLong(py_val);
        return fa->set_unsigned_value(fid, &val);
      }
    // ushort
    case 2:
      {
        ushort val = PyLong_AsUnsignedLong(py_val) & 0xffff;
        return fa->_set_field_value(fid, &val);
      }
    // strings
    case 3:
    case 1:
      {
        qstring val;
        PyUnicode_as_qstring(&val, py_val);
        return fa->set_string_value(fid, val.c_str());
      }
    // intvec_t
    case 5:
      {
        sizevec_t selection;
        if ( !PySequence_Check(py_val)
          || PyW_PySeqToSizeVec(&selection, py_val) < 0 )
        {
          break;
        }
        return fa->set_chooser_value(fid, &selection);
      }
    // Numeric
    case 6:
      {
        uint64 num;
        if ( PyW_GetNumber(py_val, &num) )
          return fa->_set_field_value(fid, &num);
      }
  }
  return false;
}

#undef DECLARE_FORM_ACTIONS

static size_t py_get_ask_form()
{
  // Return a pointer to the function. Note that, although
  // the C implementation of vask_form will do some
  // Qt/txt widgets generation, the Python's ctypes
  // implementation through which the call will go will first
  // unblock other threads. No need to do it ourselves.
  return (size_t)ask_form;
}

static size_t py_get_open_form()
{
  // See comments above.
  return (size_t)open_form;
}

static void py_register_compiled_form(PyObject *py_form)
{
#ifdef TESTABLE_BUILD
  add_test_feature("idapy:askform");
#endif
  PyW_register_compiled_form(py_form);
}

static void py_unregister_compiled_form(PyObject *py_form)
{
  PyW_unregister_compiled_form(py_form);
}
//</inline(py_kernwin_askform)>


#endif // __PY_KERNWIN_ASKFORM__

