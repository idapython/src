
#<pycode_BC695(py_segment)>
CSS_NOAREA=CSS_NORANGE
SEGDEL_KEEP=SEGMOD_KEEP
SEGDEL_KEEP0=SEGMOD_KEEP0
SEGDEL_PERM=SEGMOD_KILL
SEGDEL_SILENT=SEGMOD_SILENT
def del_segment_cmt(s, rpt):
    set_segment_cmt(s, "", rpt)
ask_selector=sel2para
# In 7.0, those were renamed
#  - get_true_segm_name -> get_segm_name
#  - get_segm_name -> get_visible_segm_name
# alas, since they have the same prototypes, we cannot do much,
# but redirect all to get_segm_name and hope for the best
get_true_segm_name=get_segm_name
#</pycode_BC695(py_segment)>
