%inline %{
//<inline(py_fpro)>
.//</inline(py_fpro)>
%}

%ignore fread2bytes;
%ignore fread4bytes;
%ignore fread8bytes;
%ignore freadbytes;
%ignore fwrite2bytes;
%ignore fwrite4bytes;
%ignore fwrite8bytes;
%ignore fwritebytes;
%ignore qaccess;
%ignore qcopyfile;
%ignore qeprintf;
//%ignore qfclose;
%ignore qfgetc;
%ignore qfgets;
%ignore qflush;
%ignore qfopen;
%ignore qfprintf;
%ignore qfputc;
%ignore qfputs;
%ignore qfread;
%ignore qfscanf;
%ignore qfseek;
%ignore qfsize;
%ignore qftell;
%ignore qfwrite;
%ignore qgetline;
%ignore qgets;
%ignore qmove;
%ignore qprintf;
%ignore qrename;
%ignore qtmpdir;
%ignore qtmpfile;
%ignore qtmpnam;
%ignore qunlink;
%ignore qveprintf;
%ignore qvfprintf;
%ignore qvfscanf;
%ignore qvprintf;

%include "fpro.h"

%pythoncode %{
#<pycode(py_fpro_end)>
#</pycode(py_fpro_end)>
%}
