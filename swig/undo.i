%{
#include <undo.hpp>
%}

// Apply a well-known recipe to `create_undo_point(const uchar *, size_t)`
%const_void_pointer_and_size(const uchar, bytes, size);

// Make the label output argument for `get_undo_action_label/get_redo_action_label`
%apply qstring *result { qstring *action_to_be_undone, qstring *action_to_be_redone};

%inline %{
// And define our own wrapper, too
bool create_undo_point(const char *action_name, const char *label)
{
  bytevec_t rec;
  rec.pack_ds(action_name);
  rec.pack_ds(label);
  return create_undo_point(rec.begin(), rec.size());
}
%}

%include "undo.hpp"
