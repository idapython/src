import subprocess
import re

# idea borrowed from implib-gen.py
def collect_syms(f, symlist = None):
  p = subprocess.Popen(["readelf", "-sDW", f], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  (out, err) = p.communicate()
  out = out.decode('utf-8')
  err = err.decode('utf-8')
  if p.returncode != 0 or err:
    error("readelf failed with retcode %d: %s" % (p.returncode, err))

  toc = None
  syms = []
  warn_versioned = False
  for line in out.splitlines():
    line = line.strip()
    if not line:
      continue
    # Num Buc:    Value          Size   Type   Bind Vis      Ndx Name
    # 492   0: 00000000005ebac0   400 OBJECT  GLOBAL DEFAULT  24 PyTraceBack_Type
    # 493   0: 00000000001cfc30    13 FUNC    GLOBAL DEFAULT  12 Py_CompileString

    words = re.split(r' +', line)
    if line.startswith('Num'):  # Header?
      if toc is not None:
        error("multiple headers in output of readelf")
      toc = {}
      for i, n in enumerate(words):
        # Colons are different across readelf versions so get rid of them.
        n = n.replace(':', '')
        toc[i] = n
    elif toc is not None:
      sym = {k: words[i] for i, k in toc.items()}
      if '@' in sym['Name']:
        name, ver = sym['Name'].split('@')
        sym['Name'] = name
        sym['Version'] = ver
        if not warn_versioned:
          # TODO
          warn("library %s contains versioned symbols which are NYI" % f)
          warn_versioned = True
      else:
        sym['Version'] = None
      if symlist and sym['Name'] not in symlist:
        continue
      syms.append(sym)

  if toc is None:
    error("failed to analyze %s" % f)

  return syms

import sys

syms = collect_syms(sys.argv[1])
for sym in syms:
   nm = sym['Name']
   sz = sym['Size']
   tp  =sym['Type']
   if sz != '0':
     if tp=="FUNC":
       print (" void %s(){};" % nm)
     elif tp =="OBJECT":
       print ('__asm__(".globl %s; .pushsection .data; .type %s,@object; .size %s, %s; %s: .zero %s; .popsection");' %(nm, nm, nm, sz, nm, sz))
