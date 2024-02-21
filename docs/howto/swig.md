
This is an FAQ-style repository of SWiG incantations that are
regularly needed.

# Remove an argument from a prototype (because it doesn't make sense in the context of IDAPython)

    %typemap(in,numinputs=0) int length
    {
        $1 = -1; // always -1 in IDAPython
    }

# Add a parameter to a C++ notification

Assume a notification named `struc_renamed`, to which you just
added a `bool success` parameter (to carry along information about the
operation's success so far):

    struc_renamed,          ///< A structure type has been renamed.
                            ///< \param sptr (::struc_t *)
                            ///< \param success (bool)  // <--------- new

That new parameter will be picked up by the hooks-producing code
automatically (great!), which means existing hooks are now broken
(bad.)

We need to add support for calling into "old-style" hooks. That's done
through the `patch_codegen.py` mechanism, and in particular the
`director_method_call_arity_cap` rule. Something like this should do:

    "SwigDirector_IDB_Hooks::struc_renamed" : [
        ("director_method_call_arity_cap", (
            False, # add GIL lock
            "struc_renamed",
            "(method ,(PyObject *)obj0,(__argcnt < 3 ? nullptr : (PyObject *)obj1), nullptr)",
            "(swig_get_self(), (PyObject *) swig_method_name ,(PyObject *)obj0,(__argcnt < 3 ? nullptr : (PyObject *)obj1), nullptr)")
        )),
    ],

# Handle a virtual method's "output" parameter in a director

Assume you have a virtual method taking an 'output' argument:

    void merge_node_helper_t::get_column_headers(qstrvec_t *out, ...)

The neat thing to do here is to let Python implementations do the
following:

    def get_column_headers(self, ...):
        # ...
        return ["Name", "Address"]

To achieve that, you want to use the `directorargout` typemap:

    %typemap(directorargout) qstrvec_t * (qstrvec_t tmp)
    { // %typemap(directorargout) qstrvec_t *
      if ( PyW_PySeqToStrVec(&tmp, $result) >= 0 )
      {
        $1->swap(tmp);
      }
      else
      {
        Swig::DirectorTypeMismatchException::raise(
                SWIG_ErrorType(SWIG_TypeError),
                "in output value of type 'qstrvec_t' in method '$symname'");
      }
    }

# "intercept" access to a structure/class field, in order to perform extra work

For example, `idainfo.lflags` bits should be set using proper setters,
because they can have side-effects.

. tell swig to consider the member as unreachable:

    %ignore idainfo::lflags;

. extend the type to "manually" provide the field:

    %extend idainfo
    {
      // ...
      uint32 _get_lflags() const { return $self->lflags; }
      void _set_lflags(uint32 _f)
      {
        // do the job here
      }

      %pythoncode {
        lflags = property(_get_lflags, _set_lflags)

