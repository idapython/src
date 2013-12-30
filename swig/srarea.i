// Ignore kernel-only symbols
%ignore create_srarea;
%ignore kill_srareras;
%ignore del_srarea;
%ignore break_srarea;
%ignore set_srarea_start;
%ignore set_srarea_end;
%ignore repairSRarea;
%ignore init_srarea;
%ignore term_srarea;
%ignore save_srarea;

#define R_es 29
#define R_cs 30
#define R_ss 31
#define R_ds 32
#define R_fs 33
#define R_gs 34

%include "srarea.hpp"
