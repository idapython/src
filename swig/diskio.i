// TODO: These could be wrapped
%ignore enumerate_files;
%ignore enumerate_system_files;
%ignore ioport_bit_t;
%ignore ioport_bits_t;
%ignore ioport_t;
%ignore read_ioports;
%ignore choose_ioport_device;
%ignore find_ioport;
%ignore find_ioport_bit;
%ignore free_ioports;
%ignore lread;
%ignore qlread;
%ignore qlgets;
%ignore qlgetc;
%ignore lreadbytes;
%ignore lread2bytes;
%ignore lread2bytes;
%ignore lread4bytes;
%ignore lread4bytes;
%ignore lread8bytes;
%ignore lread8bytes;
%ignore qlsize;
%ignore qlseek;
%ignore qltell;
%ignore qlfile;
%ignore make_linput;
%ignore unmake_linput;

// FIXME: These should be wrapped for completeness
%ignore eread;
%ignore ewrite;

// Ignore kernel-only & unexported symbols
%ignore get_thread_priority;
%ignore set_thread_priority;
%ignore checkdspace;
%ignore lowdiskgo;
%ignore ida_argv;
%ignore exename;

%include "diskio.hpp"

