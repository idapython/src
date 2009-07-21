%ignore debugger_t;

%apply unsigned char (char dtyp);

%include "idd.hpp"

%clear(char dtyp);


%inline %{
char get_event_module_name(const debug_event_t* ev, char *buf, size_t bufsize)
{
    qstrncpy(buf, ev->modinfo.name, bufsize);
    return true;
}

ea_t get_event_module_base(const debug_event_t* ev)
{
    return ev->modinfo.base;
}

asize_t get_event_module_size(const debug_event_t* ev)
{
    return ev->modinfo.size;
}

char get_event_exc_info(const debug_event_t* ev, char *buf, size_t bufsize)
{
    qstrncpy(buf, ev->exc.info, bufsize);
    return true;
}

char get_event_info(const debug_event_t* ev, char *buf, size_t bufsize)
{
    qstrncpy(buf, ev->info, bufsize);
    return true;
}

ea_t get_event_bpt_hea(const debug_event_t* ev)
{
    return ev->bpt.hea;
}

uint get_event_exc_code(const debug_event_t* ev)
{
    return ev->exc.code;
}

ea_t get_event_exc_ea(const debug_event_t* ev)
{
    return ev->exc.ea;
}

bool can_exc_continue(const debug_event_t* ev)
{
    return ev->exc.can_cont;
}
%}
