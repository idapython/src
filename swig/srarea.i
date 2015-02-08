// Ignore kernel-only symbols
%ignore repairSRarea;

%ignore init_srarea;
%ignore term_srarea;
%ignore reset_srarea;
%ignore add_srarea_from_cache;
%ignore srareas_got_loaded;
%ignore save_srarea;
%ignore create_segment_registers_area;
%ignore set_segment_register_start;
%ignore set_segment_register_end;
%ignore kill_srareras;
%ignore create_srarea;
%ignore del_srareas;
%ignore move_srareas;
%ignore delete_v660_segreg_t;
%ignore v660_segreg_t;

%ignore SRareas_get_area;
%ignore SRareas_get_area_qty;
%ignore SRareas_getn_area;
%ignore SRareas_update;
%ignore SRareas_get_area_num;
%ignore SRareas_get_next_area;
%ignore SRareas_get_prev_area;
%ignore SRareas_next_area_ptr;
%ignore SRareas_prev_area_ptr;
%ignore SRareas_first_area_ptr;
%ignore SRareas_choose_area2;
%ignore SRareas_may_start_at;
%ignore SRareas_may_end_at;
%ignore SRareas_set_start;
%ignore SRareas_set_end;
%ignore SRareas_prepare_to_create;
%ignore SRareas_create_area;
%ignore SRareas_for_all_areas2;
%ignore SRareas_del_area;

%ignore segreg_t::tag(int n);
%ignore segreg_t::reg(int n);

#define R_es 29
#define R_cs 30
#define R_ss 31
#define R_ds 32
#define R_fs 33
#define R_gs 34

%include "srarea.hpp"
