%ignore add_frame_spec_member;
%ignore del_stkvars;
%ignore calc_frame_offset;
%ignore read_regvars;
%ignore write_regvars;
%ignore del_regvars;
%ignore free_regvar;
%ignore gen_regvar_defs;
%ignore set_llabel;
%ignore get_llabel_ea;
%ignore get_llabel;
%ignore read_llabels;
%ignore write_llabels;
%ignore del_llabels;
%ignore free_llabel;
%ignore read_stkpnts;
%ignore write_stkpnts;
%ignore del_stkpnts;
%ignore rename_frame;

%ignore get_stkvar;
%rename (get_stkvar) py_get_stkvar;

%ignore add_stkvar3;
%rename (add_stkvar3) py_add_stkvar3;

%ignore calc_frame_offset;
%ignore add_stkvar;

%include "frame.hpp"
