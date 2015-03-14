# Introduction #

This is a small example on how to run Python statement from IDC and catch the errors


# Code #

```
def function():
    print "Hello...."
    print z # !!! Cause runtime errors.... !!!

err = idaapi.CompileLine(r"""
static key_ALTN()
{
  auto s = RunPythonStatement("function()");
  if (IsString(s))
  {
    Message("Error in the python statement: %s\n", s);
    return;
  }
}
""")

if err:
    print "Error compiling IDC code: %s" % err
else:
    AddHotkey("ALT-N", 'key_ALTN')
```