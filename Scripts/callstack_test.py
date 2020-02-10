from __future__ import print_function
import sys
import os

def __sys(cmd, fmt=None, echo=True):
    """Executes a string of OS commands and returns the a list of tuples (return code,command executed)"""
    if not fmt:
        fmt = {}
    r = []
    for cmd in [x for x in (cmd % fmt).split("\n") if len(x)]:
        if echo:
            print(">>>", cmd)
        r.append((os.system(cmd), cmd))
    return r

body = r"""/// Autogenerated file
#include <stdio.h>
#include <conio.h>
#include <ctype.h>
#include <windows.h>

void want_break(int n)
{
    printf("do you want to DebugBreak in func%d()?", n);
    char ch = _toupper(_getch());
    printf("\n");
    if (ch == 'Y')
        DebugBreak();
    else if (ch == 'X')
        ExitProcess(n);
}
%FUNCS%
int main(int /*argc*/, char * /*argv[]*/)
{
  func1();
  return 0;
}
"""

funcs_body = []

func_body = r"""
void func%(n)d()
{
  printf("%(ident)senter %(n)d\n");%(pause)s
  func%(n1)d();
  printf("%(ident)sleave %(n)d\n");
}
"""

if len(sys.argv) < 2:
    print("usage: gen nb_calls pause_frequency")
    sys.exit(0)

n = int(sys.argv[1])
if n < 1:
    print("at least one call should be passed!")
    sys.exit(1)

m = int(sys.argv[2])

func_params = {'n': 0, 'n1': 0, 'ident': '', 'pause' : ''}

for i in range(1, n + 1):
    func_params['n'] = i
    func_params['n1'] = i+1
    func_params['ident'] = "  " * i
    func_params['pause'] = ("\n  want_break(%d);" % i) if (i % m) == 0 else ''

    funcs_body.append(func_body % func_params)
funcs_body.append(r"""
void func%(n)d()
{
  printf("that's it #%(n)d!\n");
}
""" % {'n':i+1})
funcs_body.reverse()

# write the file
body = body.replace('%FUNCS%', ''.join(funcs_body))
f = file('src.cpp', 'w')
f.write(body)
f.close()

  
__sys("""
if exist src.exe del src.exe
bcc32 src
if exist src.exe move src.exe src_bcc.exe
if exist src.obj del src.obj
cl32 src.cpp /Zi /Od
""")