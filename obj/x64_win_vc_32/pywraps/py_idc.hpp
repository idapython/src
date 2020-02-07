
//<inline(py_idc)>
//-------------------------------------------------------------------------
inline void mark_position(
        ea_t ea,
        int lnnum,
        short x,
        short y,
        int32 slot,
        const char *comment)
{
  idaplace_t ip(ea, lnnum);
  renderer_info_t ri;
  ri.rtype = TCCRT_FLAT;
  ri.pos.cx = x;
  ri.pos.cy = y;
  lochist_entry_t loc(&ip, ri);
  bookmarks_t::mark(loc, slot, NULL, comment, NULL);
}

//-------------------------------------------------------------------------
inline ea_t get_marked_pos(int32 slot)
{
  idaplace_t ip(inf.min_ea, 0);
  renderer_info_t ri;
  lochist_entry_t loc(&ip, ri);
  uint32 uslot = uint32(slot);
  return bookmarks_t::get(&loc, NULL, &uslot, NULL)
       ? loc.place()->toea()
       : BADADDR;
}

//-------------------------------------------------------------------------
inline PyObject *get_mark_comment(int32 slot)
{
  qstring desc;
  idaplace_t ip(inf.min_ea, 0);
  renderer_info_t ri;
  lochist_entry_t loc(&ip, ri);
  if ( bookmarks_t::get_desc(&desc, loc, slot, NULL) )
    return IDAPyStr_FromUTF8(desc.c_str());
  else
    Py_RETURN_NONE;
}
//</inline(py_idc)>

