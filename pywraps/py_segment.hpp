
//<code(py_segment)>
void segment_t_startEA_set(segment_t *segm, ea_t newea)
{
  if ( getseg(segm->startEA) == segm )
  {
    PyErr_SetString(PyExc_AttributeError, "Can't modify startEA, please use set_segm_start() instead");
  }
  else
  {
    segm->startEA = newea;
  }
}

ea_t segment_t_startEA_get(segment_t *segm)
{
  return segm->startEA;
}

void segment_t_endEA_set(segment_t *segm, ea_t newea)
{
  if ( getseg(segm->startEA) == segm )
  {
    PyErr_SetString(PyExc_AttributeError, "Can't modify endEA, please use set_segm_end() instead");
  }
  else
  {
    segm->endEA = newea;
  }
}

ea_t segment_t_endEA_get(segment_t *segm)
{
  return segm->endEA;
}
//</code(py_segment)>

//<inline(py_segment)>
sel_t get_defsr(segment_t *s, int reg)
{
    return s->defsr[reg];
}
void set_defsr(segment_t *s, int reg, sel_t value)
{
    s->defsr[reg] = value;
}
//</inline(py_segment)>
