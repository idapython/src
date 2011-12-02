import types

C_TO_PY_CAST = {
  'b' : 'char',
  'i' : 'int',
  'H' : 'uint16',
  'h' : 'int16',
  'B' : 'uchar',
}
# --------------------------------------------------------------------------------------------
class gen_fmt(object):
    def __init__(self, fields, tp = None, bv = None, cast=None, cmt = None):
        self.fields = fields
        self.tp = tp
        # Format to be passed to Py_BuildValue
        if not bv:
            self.bv = "XXX"
        else:
            if bv == "K":
                self.bv = "PY_FMT64"
            else:
                self.bv = '"%s"' % bv

        if not cast:
            if bv == "K":
                cast = "pyul_t"
            elif bv in C_TO_PY_CAST:
                cast = C_TO_PY_CAST[bv]

        self.cast = "" if not cast else "(%s)" % cast
        self.cmt = cmt
        if bv == "K":
            self.setcvt = "uint64 v(0); PyGetNumber(value, &v);"
        elif bv == 'i':
            self.setcvt = "int v = PyInt_AsLong(value);"
        else:
            self.setcvt = "uint64 v = %sPyInt_AsLong(value);" % self.cast


# --------------------------------------------------------------------------------------------
switch_info_ex_t_gen = [
    gen_fmt('regdtyp', bv = 'b', cmt = 'size of the switch expression register as dtyp'),
    gen_fmt('flags2', bv = 'i'),
    gen_fmt('jcases', bv = 'i', cmt = 'number of entries in the jump table (SWI2_INDIRECT)'),
    gen_fmt('regnum', bv = 'i', cmt = 'the switch expression as a register number'),
    gen_fmt('flags', bv = 'H', cmt = 'the switch expression as a register number'),
    gen_fmt('ncases', bv = 'H', cmt = 'number of cases (excluding default)'),
    gen_fmt('defjump', bv = 'K', cmt = 'default jump address'),
    gen_fmt('jumps', bv = 'K', cmt = 'jump table address'),
    gen_fmt('elbase', bv = 'K', cmt = 'element base'),
    gen_fmt('startea', bv = 'K', cmt = 'start of switch idiom'),
    gen_fmt('custom', bv = 'K', cmt = 'information for custom tables (filled and used by modules)'),
    gen_fmt('ind_lowcase', bv = 'K'),
    gen_fmt(['values', 'lowcase'], bv = 'K'),
]

op_t_gen = [
    gen_fmt('n', bv = 'b'),
    gen_fmt('type', bv = 'B'),
    gen_fmt('offb', bv = 'b'),
    gen_fmt('offo', bv = 'b'),
    gen_fmt('flags', bv = 'B'),
    gen_fmt('dtyp', bv = 'b'),
    gen_fmt(['reg', 'phrase'], bv = 'H'),
    gen_fmt('value', bv = 'K'),
    gen_fmt('addr', bv = 'K'),
    gen_fmt('specval', bv = 'K'),
    gen_fmt('specflag1', bv = 'b'),
    gen_fmt('specflag2', bv = 'b'),
    gen_fmt('specflag3', bv = 'b'),
    gen_fmt('specflag4', bv = 'b')
]

insn_t_gen = [
    gen_fmt('cs', bv = 'K'),
    gen_fmt('ip', bv = 'K'),
    gen_fmt('ea', bv = 'K'),
    gen_fmt('itype', bv = 'H'),
    gen_fmt('size', bv = 'H'),
    gen_fmt('auxpref', bv = 'H'),
    gen_fmt('segpref', bv = 'b'),
    gen_fmt('insnpref', bv = 'b'),
    gen_fmt('Op1', tp = 'op_t'),
    gen_fmt('Op2', tp = 'op_t'),
    gen_fmt('Op3', tp = 'op_t'),
    gen_fmt('Op4', tp = 'op_t'),
    gen_fmt('Op5', tp = 'op_t'),
    gen_fmt('Op6', tp = 'op_t'),
    gen_fmt('flags', bv = 'b')
]

regval_t_gen = [
    gen_fmt('rvtype', bv = 'i'),
    gen_fmt('ival', bv = 'K'),
    gen_fmt('fval', bv = 'd'),
    gen_fmt('bytes', bv = 's'),
]

# --------------------------------------------------------------------------------------------
S_LINK_ATTR = 'S_CLINK_NAME' # If the name is a literal, make sure you specify double quotations
S_CMOD_NAME = '_idaapi'

# --------------------------------------------------------------------------------------------
def gen_stub(gen, name, cname = None, tabs=4, gen_py_file = False, gen_c_file = False):
    # Assume C type name same as python type name
    if not cname:
        cname = name

    # Python property lines
    prop_body = []

    # Python get/set bodies
    getset_body = []

    # C get/set bodies
    cgetset_body = []

    # some spacing constants
    spc   = ' ' * tabs
    spc2  = spc * 2
    nspc  = '\n' + spc
    nspc2 = '\n' + spc2

    cget_link = '%s_get_clink' % cname

    #
    # Process fields
    #
    for g in gen:
        # a union will be represented by a list
        if type(g.fields) != types.ListType:
            fields = [g.fields]
        else:
            fields = g.fields

        # join all field names (in case of a union)
        flds_name  = '_'.join(fields)

        # form the method and variable names
        set_method = '__set_%s__' % flds_name
        get_method = '__get_%s__' % flds_name
        cset_method = '%s_set_%s' % (name, flds_name)
        cget_method = '%s_get_%s' % (name, flds_name)
        fld_name   = '__%s__' % flds_name

        basic_type = not g.tp

        vars = {
            'get': get_method,
            'set': set_method,
            'l': S_LINK_ATTR,
            'fld' : fld_name,
            'cmod' : S_CMOD_NAME,
            'cget': cget_method,
            'cset': cset_method,
            'csetcvt': g.setcvt,
            'cname': cname,
            'cgetlink': cget_link,
            'cfield1': fields[0],
            'bv': g.bv,
            'bvcast': g.cast
        }

        #
        # Python code
        #

        # basic type?
        # For basic types we need to create property and get/set methods
        if basic_type:
            for fld in fields:
                prop_body.append('%s = property(%s, %s)' % (fld, get_method, set_method))
                if g.cmt:
                    prop_body.append('"""%s"""' % g.cmt)

            #
            code = '\n'.join([
              # get method
              'def %(get)s(self):',
              spc2 + 'return %(cmod)s.%(cget)s(self)',
              # set method
              spc  + 'def %(set)s(self, v):',
              spc2 + '%(cmod)s.%(cset)s(self, v)',
            ]) % vars

            getset_body.append(code)

        #
        # C code
        #
        if basic_type:
            code = '\n'.join([
"""static PyObject *%(cget)s(PyObject *self)
{
  %(cname)s *link = %(cgetlink)s(self);
  if ( link == NULL )
    Py_RETURN_NONE;
  return Py_BuildValue(%(bv)s, %(bvcast)slink->%(cfield1)s);
}
static void %(cset)s(PyObject *self, PyObject *value)
{
  %(cname)s *link = %(cgetlink)s(self);
  if ( link == NULL )
    return;
  %(csetcvt)s
  link->%(cfield1)s = %(bvcast)sv;
}

"""
            ]) % vars

            cgetset_body.append(code)

#    print 'prop_body->\n\t', '\n\t'.join(prop_body), '\n<'
#    print 'getset_body->\n', '\n'.join(getset_body), '\n<'
#    print 'cgetset_body->\n', '\n'.join(cgetset_body), '\n<'

    vars = {
        'name': name,
        'cname': cname,
        'getlink': cget_link,
        'l': S_LINK_ATTR,
        'cmod' : S_CMOD_NAME
    }

    #
    # Form the complete Python code
    #
    py = '\n'.join([
        'class %(name)s(py_clinked_object_t):',

        # init() code
        spc  + 'def __init__(self, lnk = None):',
        spc2 + 'py_clinked_object_t.__init__(self, lnk)',
        '',
        spc  + 'def _create_clink(self):',
        spc2 + 'return _idaapi.%(name)s_create()',
        '',
        spc  + 'def _del_clink(self, lnk):',
        spc2 + 'return _idaapi.%(name)s_destroy(lnk)',
        '',
        spc  + 'def assign(self, other):',
        spc2 + 'return _idaapi.%(name)s_assign(self, other)',
        '',
        '',
        spc + '#',
        spc + '# Autogenerated',
        spc + '#',
        # get/set code
        spc + nspc.join(getset_body),
        # props code
        spc + nspc.join(prop_body),
    ]) % vars

    #
    # Form the Python to C conversion function
    #

    #
    # Form the complete C code
    #
    ccode = '\n'.join([
    # Form the C get link code
"""%(cname)s *%(getlink)s(PyObject *self)
{
  if ( !PyObject_HasAttrString(self, %(l)s) )
    return NULL;
  %(cname)s *r;
  PyObject *attr = PyObject_GetAttrString(self, %(l)s);
  if ( PyCObject_Check(attr) )
    r = (%(cname)s *) PyCObject_AsVoidPtr(attr);
  else
    r = NULL;
  Py_DECREF(attr);
  return r;
}

static PyObject *%(cname)s_create()
{
  %(cname)s *inst = new %(cname)s();
  return PyCObject_FromVoidPtr(inst, NULL);
}

static bool %(cname)s_destroy(PyObject *py_obj)
{
  if ( !PyCObject_Check(py_obj) )
    return false;
  %(cname)s *inst = (%(cname)s *) PyCObject_AsVoidPtr(py_obj);
  delete inst;
  return true;
}

static bool %(cname)s_assign(PyObject *self, PyObject *other)
{
  %(cname)s *lhs = %(cname)s_get_clink(self);
  %(cname)s *rhs = %(cname)s_get_clink(other);
  if (lhs == NULL || rhs == NULL)
    return false;

  *lhs = *rhs;
  return true;
}

//-------------------------------------------------------------------------
// Auto generated - begin
//
""",
    # Form C get/set functions
    ''.join(cgetset_body),
"""//
// Auto generated - end
//
//-------------------------------------------------------------------------"""
    ]) % vars

    # write the Python file
    if gen_py_file:
        f = open(name + '.py', 'w')
        f.write(py)
        f.close()

    # write C file
    if gen_c_file:
        f = open(name + '.cpp', 'w')
        f.write(ccode)
        f.close()

# --------------------------------------------------------------------------------------------
def main():
    files = [
        ('switch_info_ex_t', switch_info_ex_t_gen),
    ]
    for (n, g) in files:
        gen_stub(g, n, gen_py_file = True, gen_c_file = True)

main()