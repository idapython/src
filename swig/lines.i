// FIXME: These should be fixed
%ignore requires_color_esc;
%ignore tag_on;
%ignore tag_remove;
%ignore tag_off;
%ignore tag_addchr;
%ignore tag_addstr;
%ignore tag_addr;
%ignore tag_advance;
%ignore tag_skipcodes;
%ignore tag_skipcode;
%ignore set_user_defined_prefix;
%ignore get_user_defined_prefix;
// Ignore va_list versions
%ignore printf_line_v;
%ignore gen_colored_cmt_line_v;
%ignore gen_cmt_line_v;
%ignore add_long_cmt_v;
%ignore describex;
// Kernel-only and unexported symbols
%ignore init_sourcefiles;
%ignore save_sourcefiles;
%ignore term_sourcefiles;
%ignore move_sourcefiles;
%ignore gen_xref_lines;
%ignore ml_getcmt_t;
%ignore ml_getnam_t;
%ignore ml_genxrf_t;
%ignore ml_saver_t;
%ignore setup_makeline;
%ignore MAKELINE_NONE;
%ignore MAKELINE_BINPREF;
%ignore MAKELINE_VOID;
%ignore MAKELINE_STACK;
%ignore save_line_in_array;
%ignore init_lines_array;
%ignore finish_makeline;
%ignore generate_disassembly;
%ignore gen_labeled_line;
%ignore gen_lname_line;
%ignore makeline_producer_t;
%ignore set_makeline_producer;
%ignore closing_comment;
%ignore close_comment;
%ignore copy_extra_lines;
%ignore ExtraLines;
%ignore ExtraKill;
%ignore ExtraFree;
%ignore Dumper;
%ignore init_lines;
%ignore save_lines;
%ignore term_lines;
%ignore gl_namedone;
%ignore data_as_stack;
%ignore calc_stack_alignment;
%ignore align_down_to_stack;
%ignore align_up_to_stack;
%ignore remove_spaces;

%include "lines.hpp"

%rename (generate_disassembly) py_generate_disassembly;
%rename (tag_remove) py_tag_remove;
%rename (tag_addr) py_tag_addr;
%rename (tag_skipcodes) py_tag_skipcodes;
%rename (tag_skipcode) py_tag_skipcode;
%rename (tag_advance) py_tag_advance;
%rename (generate_disassembly) py_generate_disassembly;

%inline 
{
//<inline(py_lines)>
//-------------------------------------------------------------------------
PyObject *py_tag_remove(const char *instr)
{
  size_t sz = strlen(instr);
  char *buf = new char[sz + 5];
  if ( buf == NULL )
    Py_RETURN_NONE;
  ssize_t r = tag_remove(instr, buf, sz);
  PyObject *res;
  if ( r < 0 )
  {
    Py_INCREF(Py_None);
    res = Py_None;
  }
  else
  {
    res = PyString_FromString(buf);
  }
  delete [] buf;
  return res;
}

//-------------------------------------------------------------------------
PyObject *py_tag_addr(ea_t ea)
{
  char buf[100];
  tag_addr(buf, buf + sizeof(buf), ea);
  return PyString_FromString(buf);
}

//-------------------------------------------------------------------------
int py_tag_skipcode(const char *line)
{
  return tag_skipcode(line)-line;
}

//-------------------------------------------------------------------------
int py_tag_skipcodes(const char *line)
{
  return tag_skipcodes(line)-line;
}

//-------------------------------------------------------------------------
int py_tag_advance(const char *line, int cnt)
{
  return tag_advance(line, cnt)-line;
}

//-------------------------------------------------------------------------
PyObject *py_generate_disassembly(ea_t ea, int max_lines, bool as_stack, bool notags)
{
  if ( max_lines <= 0 )
    Py_RETURN_NONE;

  qstring qbuf;
  char **lines = new char *[max_lines];
  int lnnum;
  int nlines = generate_disassembly(ea, lines, max_lines, &lnnum, as_stack);

  PyObject *py_tuple = PyTuple_New(nlines);
  for ( int i=0; i<nlines; i++ )
  {
    const char *s = lines[i];
    size_t line_len = strlen(s);
    if ( notags )
    {
      qbuf.resize(line_len+5);
      tag_remove(s, &qbuf[0], line_len);
      s = (const char *)&qbuf[0];
    }
    PyTuple_SetItem(py_tuple, i, PyString_FromString(s));
    qfree(lines[i]);
  }
  delete [] lines;
  PyObject *py_result = Py_BuildValue("(iO)", lnnum, py_tuple);
  Py_DECREF(py_tuple);
  return py_result;
}
//</inline(py_lines)>

}

%pythoncode %{
#<pycode(py_lines)>

# ---------------- Color escape sequence defitions -------------------------
COLOR_ADDR_SIZE = 16 if _idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL else 8
SCOLOR_FG_MAX   = '\x28'             #  Max color number
SCOLOR_OPND1    = chr(cvar.COLOR_ADDR+1)  #  Instruction operand 1
SCOLOR_OPND2    = chr(cvar.COLOR_ADDR+2)  #  Instruction operand 2
SCOLOR_OPND3    = chr(cvar.COLOR_ADDR+3)  #  Instruction operand 3
SCOLOR_OPND4    = chr(cvar.COLOR_ADDR+4)  #  Instruction operand 4
SCOLOR_OPND5    = chr(cvar.COLOR_ADDR+5)  #  Instruction operand 5
SCOLOR_OPND6    = chr(cvar.COLOR_ADDR+6)  #  Instruction operand 6
SCOLOR_UTF8     = chr(cvar.COLOR_ADDR+10) #  Following text is UTF-8 encoded

# ---------------- Line prefix colors --------------------------------------
PALETTE_SIZE   =  (cvar.COLOR_FG_MAX+_idaapi.COLOR_BG_MAX)

def requires_color_esc(c):
    """
    Checks if the given character requires escaping
    @param c: character (string of one char)
    @return: Boolean
    """
    t = ord(c[0])
    return c >= COLOR_ON and c <= COLOR_INV

def COLSTR(str,tag):
    return SCOLOR_ON + tag + str + SCOLOR_OFF + tag

#</pycode(py_lines)>

%}