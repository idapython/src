%{
#include <diskio.hpp>
#include <expr.hpp>
#include <loader.hpp>
#include "../../../pywraps.hpp"
%}

// TODO: These could be wrapped
%ignore enumerate_files;
%rename (enumerate_files) py_enumerate_files;
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
%ignore linput_buffer_t;

%ignore eread;
%ignore ewrite;
%ignore eseek;
%ignore ecreate;
%ignore openR;
%ignore openRT;
%ignore openM;
// some of these functions are used in idc.py:
// %ignore eclose;
// %ignore fopenWT;
// %ignore fopenWB;
// %ignore fopenRT;
// %ignore fopenRB;
// %ignore fopenM;
// %ignore fopenA;

%apply Pointer NONNULL { linput_t *li };

%ignore qfsize;
%ignore echsize;
%ignore get_free_disk_space;
%ignore call_system;

// Ignore kernel-only & unexported symbols
%ignore get_thread_priority;
%ignore lowdiskgo;
%ignore ida_argv;
%ignore exename;

%ignore create_bytearray_linput;
%rename (create_bytearray_linput) py_create_bytearray_linput;

%ignore close_linput;
%rename (close_linput) py_close_linput;

%apply qstrvec_t *out { qstrvec_t *dirs };

%cstring_output_buf_and_size_returning_charptr(
        1,
        char *buf,
        size_t bufsize,
        const char *filename,
        const char *subdir); // getsysfile
%cstring_output_buf_and_size_returning_charptr(
        3,
        linput_t *li,
        int64 fpos,
        char *buf,
        size_t bufsize); // qlgetz

%include "diskio.hpp"

%{
//<code(py_diskio)>
//</code(py_diskio)>
%}

%inline %{
//<inline(py_diskio)>
//</inline(py_diskio)>
%}

%pythoncode %{
#<pycode(py_diskio)>
#</pycode(py_diskio)>
%}
