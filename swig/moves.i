%{
#include <moves.hpp>
%}
// Ignore kernel only symbols
%ignore move_marks;
%ignore curloc_after_segments_moved;
%ignore curloc::rebase_stack;
%ignore DEFINE_CURLOC_HELPERS;
%ignore DEFINE_LOCATION_HELPERS;
%ignore lochist_t::rebase_stack;
%ignore location_t::location_t(bool);
%ignore lochist_t::is_hexrays68_compat;
%ignore lochist_entry_t::set_place(const place_t &);
%ignore lochist_entry_t::serialize;
%ignore lochist_entry_t::deserialize;
%ignore graph_location_info_t::serialize(bytevec_t *) const;
%ignore graph_location_info_t::deserialize(memory_deserializer_t &);
%ignore renderer_info_pos_t::serialize(bytevec_t *) const;
%ignore renderer_info_pos_t::deserialize(memory_deserializer_t &);
%ignore bookmarks_t_get;
%ignore bookmarks_t::get(lochist_entry_t *, qstring *, uint32 *, void *);

%template(segm_move_info_vec_t) qvector<segm_move_info_t>;

%apply SWIGTYPE *DISOWN { place_t *in_p };

%inline %{
//<inline(py_moves)>
//</inline(py_moves)>
%}

%pythoncode %{
#<pycode(py_moves)>
#</pycode(py_moves)>
%}

// bookmarks_t::get
%extend bookmarks_t {
  static PyObject *get(lochist_entry_t *out, uint32 _index, void *ud)
  {
    uint32 index = _index;
    qstring desc;
    return bookmarks_t::get(out, &desc, &index, ud)
         ? Py_BuildValue("(sI)", desc.c_str(), index)
         : Py_BuildValue("(OO)", Py_None, Py_None);
  }

  %pythoncode {
      def __init__(self, w):
          """
          Build an object suitable for iterating bookmarks
          associated with the specified widget.

          Note: all ea_t-based widgets (e.g., "IDA View-*",
          "Pseudocode-*", "Hex View-*", ...) share a common storage,
          so bookmarks can be re-used interchangeably between them
          """
          self.widget = w
          self.userdata = ida_kernwin.get_viewer_user_data(self.widget)
          self.template = lochist_entry_t()
          if ida_kernwin.get_custom_viewer_location(self.template, self.widget):
              p = self.template.place()
              if p is not None:
                  p_id = ida_kernwin.get_place_class_id(p.name())
                  if p_id > -1 and ida_kernwin.is_place_class_ea_capable(p_id):
                      idap_id = ida_kernwin.get_place_class_id("idaplace_t")
                      if idap_id > -1:
                          idap = ida_kernwin.get_place_class_template(idap_id)
                          if idap is not None:
                              self.template.set_place(idap)

      def __iter__(self):
          """
          Iterate on bookmarks present for the widget.
          """
          p = self.template.place()
          if p is not None:
              for idx in range(bookmarks_t.size(self.template, self.userdata)):
                  yield self[idx]

      def __len__(self):
          """
          Get the number of bookmarks for the widget.
          """
          return bookmarks_t.size(self.template, self.userdata)

      def __getitem__(self, idx):
          """
          Get the n-th bookmark for the widget.
          """
          p = self.template.place()
          if p is not None:
              if isinstance(idx, int) and idx >= 0 and idx < len(self):
                  loc = lochist_entry_t()
                  loc.set_place(p)
                  desc, _ = bookmarks_t.get(loc, idx, self.userdata)
                  return loc, desc
              else:
                  raise IndexError()
  }
}

%include "moves.hpp"
