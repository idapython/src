// Ignore kernel only & unexported symbols
%ignore netlink;

%ignore RootNode;
%ignore for_all_supvals;
%ignore netErrorHandler;
%ignore netnode_key_count;

%ignore netnode_check;
%ignore netnode_kill;
%ignore netnode_start;
%ignore netnode_end;
%ignore netnode_next;
%ignore netnode_prev;
%ignore netnode_name;
%ignore netnode_rename;
%ignore netnode_valobj;
%ignore netnode_valstr;
%ignore netnode_set;
%ignore netnode_delvalue;
%ignore netnode_altval;
%ignore netnode_charval;
%ignore netnode_altval_idx8;
%ignore netnode_charval_idx8;
%ignore netnode_supval;
%ignore netnode_supstr;
%ignore netnode_supset;
%ignore netnode_supdel;
%ignore netnode_sup1st;
%ignore netnode_supnxt;
%ignore netnode_suplast;
%ignore netnode_supprev;
%ignore netnode_supval_idx8;
%ignore netnode_supstr_idx8;
%ignore netnode_supset_idx8;
%ignore netnode_supdel_idx8;
%ignore netnode_sup1st_idx8;
%ignore netnode_supnxt_idx8;
%ignore netnode_suplast_idx8;
%ignore netnode_supprev_idx8;
%ignore netnode_supdel_all;
%ignore netnode_supdel_range;
%ignore netnode_supdel_range_idx8;
%ignore netnode_hashval;
%ignore netnode_hashstr;
%ignore netnode_hashval_long;
%ignore netnode_hashset;
%ignore netnode_hashdel;
%ignore netnode_hash1st;
%ignore netnode_hashnxt;
%ignore netnode_hashlast;
%ignore netnode_hashprev;
%ignore netnode_blobsize;
%ignore netnode_getblob;
%ignore netnode_setblob;
%ignore netnode_delblob;
%ignore netnode_inited;
%ignore netnode_copy;
%ignore netnode_altshift;
%ignore netnode_charshift;
%ignore netnode_supshift;
%ignore netnode_altadjust;
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
%ignore netnode::getblob(void *buf, size_t *bufsize, nodeidx_t start, char tag);
%ignore netnode::operator nodeidx_t;
%ignore netnode::validate_names;

// Renaming one version of hashset() otherwise SWIG will not be able to activate the other one
%rename (hashset_idx) netnode::hashset(const char *idx, nodeidx_t value, char tag=htag);

%include "netnode.hpp"

%extend netnode
{
    nodeidx_t index()
    {
      return self->operator nodeidx_t();
    }

    PyObject *getblob(nodeidx_t start, const char *tag)
    {
      // Get the blob and let IDA allocate the memory
      size_t bufsize;
      void *buf = self->getblob(NULL, &bufsize, start, *tag);
      if ( buf == NULL )
        Py_RETURN_NONE;
      // Create a Python string
      PyObject *py_str = PyString_FromStringAndSize((const char *)buf, bufsize);
      // Free memory
      qfree(buf);

      return py_str;
    }

    PyObject *hashstr_buf(const char *idx, char tag=htag)
    {
      char buf[MAXSPECSIZE];
      ssize_t sz = self->hashstr(idx, buf, sizeof(buf), tag);
      if ( sz < 0 )
        Py_RETURN_NONE;
      else
        return PyString_FromStringAndSize(buf, sz);
    }

    bool hashset_buf(const char *idx, PyObject *py_str, char tag=htag)
    {
      char *buf;
      Py_ssize_t sz;

      if ( PyString_AsStringAndSize(py_str, &buf, &sz) == -1 )
        return false;
      else
        return self->hashset(idx, buf, sz, tag);
    }
}
