
//<code(py_segment)>
void segment_t_start_ea_set(segment_t *segm, ea_t newea)
{
  if ( getseg(segm->start_ea) == segm )
  {
    PyErr_SetString(PyExc_AttributeError, "Can't modify start_ea, please use set_segm_start() instead");
  }
  else
  {
    segm->start_ea = newea;
  }
}

ea_t segment_t_start_ea_get(segment_t *segm)
{
  return segm->start_ea;
}

void segment_t_end_ea_set(segment_t *segm, ea_t newea)
{
  if ( getseg(segm->start_ea) == segm )
  {
    PyErr_SetString(PyExc_AttributeError, "Can't modify end_ea, please use set_segm_end() instead");
  }
  else
  {
    segm->end_ea = newea;
  }
}

ea_t segment_t_end_ea_get(segment_t *segm)
{
  return segm->end_ea;
}
//</code(py_segment)>

//<inline(py_segment)>
//--------------------------------------------------------------------------
/*
#<pydoc>
def get_defsr(s, reg):
    """
    Deprecated, use instead:
        value = s.defsr[reg]
    """
    pass
#</pydoc>
*/
sel_t get_defsr(segment_t *s, int reg)
{
  return s != nullptr && reg >= 0 && reg < SREG_NUM ? s->defsr[reg] : BADSEL;
}

//--------------------------------------------------------------------------
/*
#<pydoc>
def set_defsr(s, reg, value):
    """
    Deprecated, use instead:
        s.defsr[reg] = value
    """
    pass
#</pydoc>
*/
void set_defsr(segment_t *s, int reg, sel_t value)
{
  if ( s != nullptr && reg >= 0 && reg < SREG_NUM )
    s->defsr[reg] = value;
}

//--------------------------------------------------------------------------
int py_rebase_program(PyObject *delta, int flags)
{
  int rc = MOVE_SEGM_PARAM;
  uint64 num_delta;
  if ( PyW_GetNumber(delta, &num_delta) )
    rc = rebase_program(adiff_t(num_delta), flags);
  else
    PyErr_SetString(PyExc_TypeError, "Expected a delta in bytes");
  return rc;
}
//</inline(py_segment)>
