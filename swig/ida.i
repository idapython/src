// Ignore kernel-only symbols
%ignore dual_text_options_t;
%ignore idainfo::init;
%ignore idainfo::retrieve;
%ignore idainfo::read;
%ignore idainfo::write;
%ignore idainfo::align_short_demnames;
%ignore idainfo::align_strtype;
%ignore idainfo::align_long_demnames;

%ignore setflag(uchar &where,uchar bit,int value);
%ignore setflag(ushort &where,ushort bit,int value);
%ignore setflag(uint32 &where,uint32 bit,int value);

// Make idainfo::get_proc_name() work
%cstring_bounded_output(char *buf, 8);

%ignore BADADDR;
%ignore BADSEL;

%include "ida.hpp"

%clear(char *buf);
