# HOW-TO

### How to add new module?

We use the "zzz" placeholder for a module name in this "how-to".

1. create file swig/zzz.i
```
%{
#include <zzz.hpp>
%}
%include "zzz.hpp"
```

2. add zzz to the `MODULES_NAMES` var in makefile

3. add a line to python/idc.py if you want to autoload this module
```
import ida_zzz
```

4. build

5. update the content of api_contents.txt
   (from obj/.../api_contents.txt.new)

6. rebuild

7. update the content of pydoc_injections.txt
   (from obj/.../pydoc_injections.txt)
