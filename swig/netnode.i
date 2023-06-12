%ignore RootNode;

%ignore netnode_check;
%ignore netnode_kill;
%ignore netnode_start;
%ignore netnode_end;
%ignore netnode_next;
%ignore netnode_prev;
%ignore netnode_get_name;
%ignore netnode_rename;
%ignore netnode_valobj;
%ignore netnode_valstr;
%ignore netnode_qvalstr;
%ignore netnode::valstr(char*,size_t) const;
%ignore netnode_set;
%ignore netnode_delvalue;
%ignore netnode_altval;
%ignore netnode_charval;
%ignore netnode_altval_idx8;
%ignore netnode_charval_idx8;
%ignore netnode_supval;
%ignore netnode_supstr;
%ignore netnode_qsupstr;
%ignore netnode::supstr(nodeidx_t,char*,size_t,uchar) const;
%ignore netnode_supstr_ea;
%ignore netnode_qsupstr_ea;
%ignore netnode::supstr_ea(ea_t,char*,size_t,uchar) const;
%ignore netnode_supset;
%ignore netnode_supdel;
%ignore netnode_lower_bound;
%ignore netnode_supfirst;
%ignore netnode_supnext;
%ignore netnode_suplast;
%ignore netnode_supprev;
%ignore netnode_supval_idx8;
%ignore netnode_supstr_idx8;
%ignore netnode_qsupstr_idx8;
%ignore netnode::supstr_idx8(uchar,char*,size_t,uchar) const;
%ignore netnode_supset_idx8;
%ignore netnode_supdel_idx8;
%ignore netnode_lower_bound_idx8;
%ignore netnode_supfirst_idx8;
%ignore netnode_supnext_idx8;
%ignore netnode_suplast_idx8;
%ignore netnode_supprev_idx8;
%ignore netnode_supdel_all;
%ignore netnode_supdel_range;
%ignore netnode_supdel_range_idx8;
%ignore netnode_hashval;
%ignore netnode_hashstr;
%ignore netnode_qhashstr;
%ignore netnode::hashstr(const char*,char*,size_t,uchar) const;
%ignore netnode_hashval_long;
%ignore netnode_hashset;
%ignore netnode_hashdel;
%ignore netnode_hashfirst;
%ignore netnode_qhashfirst;
%ignore netnode::hashfirst(char*,size_t,uchar) const;
%ignore netnode_hashnext;
%ignore netnode_qhashnext;
%ignore netnode::hashnext(const char*,char*,size_t,uchar) const;
%ignore netnode_hashlast;
%ignore netnode_qhashlast;
%ignore netnode::hashlast(char*,size_t,uchar) const;
%ignore netnode_hashprev;
%ignore netnode_qhashprev;
%ignore netnode::hashprev(const char*,char*,size_t,uchar) const;
%ignore netnode_blobsize;
%ignore netnode_getblob;
%ignore netnode_qgetblob;
%ignore netnode_setblob;
%ignore netnode_delblob;
%ignore netnode_inited;
%ignore netnode_is_available;
%ignore netnode_copy;
%ignore netnode_copy2;
%ignore netnode_copyto2;
%ignore netnode_altshift;
%ignore netnode_charshift;
%ignore netnode_supshift;
%ignore netnode_blobshift;
%ignore netnode_altadjust;
%ignore netnode_altadjust2;
%ignore altadjust_visitor_t;
%ignore netnode_exist;

%ignore netnode::truncate_zero_pages;
%ignore netnode::append_zero_pages;
%ignore netnode::createbase;
%ignore netnode::checkbase;
%ignore netnode::set_close_flag;
%ignore netnode::reserve_nodes;
%ignore netnode::validate;
%ignore netnode::upgrade16;
%ignore netnode::upgrade;
%ignore netnode::compress;
%ignore netnode::inited;
%ignore netnode::is_available;
%ignore netnode::init;
%ignore netnode::can_write;
%ignore netnode::flush;
%ignore netnode::get_linput;
%ignore netnode::term;
%ignore netnode::killbase;
%ignore netnode::getdrive;
%ignore netnode::getgraph;
%ignore netnode::registerbase;
%ignore netnode::setbase;

%ignore netnode::altadjust;
%ignore netnode::altadjust2;
%ignore netnode::getblob(qstring *buf, nodeidx_t start, uchar tag);
%ignore netnode::getblob(void *buf, size_t *bufsize, nodeidx_t start, uchar tag);
%ignore netnode::getblob_ea(void *buf, size_t *bufsize, ea_t ea, uchar tag);
%ignore netnode::operator nodeidx_t;
%ignore netnode::validate_names;

%constant nodeidx_t BADNODE = nodeidx_t(-1);
%constant size_t SIZEOF_nodeidx_t = sizeof(nodeidx_t);

// Renaming one version of hashset() otherwise SWIG will not be able to activate the other one
%rename (hashset_idx) netnode::hashset(const char *idx, nodeidx_t value, uchar tag=htag);

%define_netnode_tag_accessors();

%include "netnode.hpp"

%extend netnode
{
    nodeidx_t index()
    {
      return self->operator nodeidx_t();
    }

    PyObject *getblob(nodeidx_t start, char tag)
    {
      bytevec_t blob;
      if ( self->getblob(&blob, start, uchar(tag)) <= 0 )
        Py_RETURN_NONE;
      return PyBytes_FromStringAndSize((const char *)blob.begin(), blob.size());
    }

    PyObject *getclob(nodeidx_t start, char tag)
    {
      qstring clob;
      if ( self->getblob(&clob, start, uchar(tag)) <= 0 )
        Py_RETURN_NONE;
      return PyUnicode_FromStringAndSize((const char *)clob.begin(), clob.length());
    }

    PyObject *getblob_ea(ea_t ea, char tag)
    {
      bytevec_t blob;
      if ( self->getblob(&blob, ea, tag) <= 0 )
        Py_RETURN_NONE;
      return PyBytes_FromStringAndSize((const char *)blob.begin(), blob.size());
    }

    PyObject *hashstr_buf(const char *idx, char tag=htag)
    {
      char buf[MAXSPECSIZE];
      ssize_t sz = self->hashstr(idx, buf, sizeof(buf), uchar(tag));
      if ( sz < 0 )
        Py_RETURN_NONE;
      else
        return PyUnicode_FromStringAndSize(buf, sz);
    }

    bool hashset_buf(const char *idx, PyObject *py_str, char tag=htag)
    {
      qstring buf;
      return PyUnicode_as_qstring(&buf, py_str)
          && self->hashset(idx, buf.c_str(), buf.length(), uchar(tag));
    }

    bool supset(nodeidx_t alt, const char *value, size_t length=0, uchar tag=stag)
    {
      return self->supset(alt, (void *) value, length, tag);
    }

    bool supset_ea(ea_t ea, const char *value, size_t length=0, uchar tag=stag)
    {
      return self->supset_ea(ea, (void *) value, length, tag);
    }
}
