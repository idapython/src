%module(docstring="IDA Plugin SDK API wrapper: problems",directors="1",threads="1") ida_problems
#ifndef IDA_MODULE_DEFINED
  #define IDA_MODULE_PROBLEMS
#define IDA_MODULE_DEFINED
#endif // IDA_MODULE_DEFINED
#ifndef HAS_DEP_ON_INTERFACE_PROBLEMS
  #define HAS_DEP_ON_INTERFACE_PROBLEMS
#endif
%include "header.i"
%{
#include <problems.hpp>
%}

%include "problems.hpp"
%pythoncode %{
if _BC695:
    import sys
    sys.modules["ida_queue"] = sys.modules["ida_problems"]
    Q_Qnum=_ida_problems.cvar.PR_END
    Q_att=_ida_problems.cvar.PR_ATTN
    Q_badstack=_ida_problems.cvar.PR_BADSTACK
    Q_collsn=_ida_problems.cvar.PR_COLLISION
    Q_decimp=_ida_problems.cvar.PR_DECIMP
    Q_disasm=_ida_problems.cvar.PR_DISASM
    Q_final=_ida_problems.cvar.PR_FINAL
    Q_head=_ida_problems.cvar.PR_HEAD
    Q_jumps=_ida_problems.cvar.PR_JUMP
    Q_lines=_ida_problems.cvar.PR_MANYLINES
    Q_noBase=_ida_problems.cvar.PR_NOBASE
    Q_noComm=_ida_problems.cvar.PR_NOCMT
    Q_noFop=_ida_problems.cvar.PR_NOFOP
    Q_noName=_ida_problems.cvar.PR_NONAME
    Q_noRef=_ida_problems.cvar.PR_NOXREFS
    Q_noValid=_ida_problems.cvar.PR_ILLADDR
    Q_rolled=_ida_problems.cvar.PR_ROLLED
    QueueDel=forget_problem
    QueueGetMessage=get_problem_desc
    QueueGetType=get_problem
    QueueIsPresent=is_problem_present
    QueueSet=remember_problem
    def get_long_queue_name(t):
        return get_problem_name(t, True)
    def get_short_queue_name(t):
        return get_problem_name(t, False)

%}