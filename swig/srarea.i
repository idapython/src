// Ignore kernel-only symbols
%ignore createSRarea;
%ignore killSRareas;
%ignore delSRarea;
%ignore SRareaStart;
%ignore SRareaEnd;
%ignore repairSRarea;
%ignore SRinit;
%ignore SRterm;
%ignore SRsave;

#define R_es 29
#define R_cs 30
#define R_ss 31
#define R_ds 32
#define R_fs 33
#define R_gs 34

%feature("compactdefaultargs") splitSRarea1;

%include "srarea.hpp"
