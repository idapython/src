# -----------------------------------------------------------------------
# This script is used to extract embedded documentation strings
# from SWIG interface files.
# (c) Hex-Rays
#
import glob
import sys

# ---------------------------------------------------------------------------
def extract_docs(lines, out):
    S_SWIG_CLOSE    = '%}'
    S_PYDOC_START   = '#<pydoc>'
    S_PYDOC_END     = '#</pydoc>'
    S_COMMENT       = '#'
    S_INLINE        = '%inline %{'
    S_PYCODE_START  = '%pythoncode %{'

    in_inline = False
    in_pythoncode = False
    in_pydoc = False

    for line in lines:
        line = line.rstrip()
        # skip empty lines
        if not line:
            continue

        # Inside pythoncode tag?
        if in_pythoncode:
            if line == S_PYDOC_START:
                in_pydoc = True
                continue
            elif line == S_PYDOC_END:
                in_pydoc = False
                continue
            elif line == S_SWIG_CLOSE:
                in_pythoncode = False
                continue
            # Skip unneeded tags
            elif line[:8] == '#<pycode' or line[:9] == '#</pycode':
                continue
            # In pydoc? uncomment the lines
            elif in_pydoc:
                if line[0] == S_COMMENT:
                    line = line[1:]
            # All lines in pythoncode section are extracted
            out.append(line)

        # Inside inline tag?
        elif in_inline:
            if line == S_PYDOC_START:
                in_pydoc = True
                continue
            elif line == S_SWIG_CLOSE:
                in_inline = False
                continue
            elif line == S_PYDOC_END:
                in_pydoc = False
                continue
            # Extract lines in cpydoc only
            elif in_pydoc:
                out.append(line)
        # Detect tags
        elif line == S_PYCODE_START:
            in_pythoncode = True
            continue
        elif line == S_INLINE:
            in_inline = True

# ---------------------------------------------------------------------------
def gen_docs(path = '../swig/', outfn = 'idaapi.py', mask = '*.i'):
    out = []
    for fn in glob.glob(path + mask):
        f = open(fn, 'r')
        lines = f.readlines()
        f.close()
        extract_docs(lines, out)

    f = open(outfn, 'w')
    f.write('"""This is a placeholder module used to document all the IDA SDK functions that are wrapped manually. You still need to import \'idaapi\' and not this module to use the functions"""\n')
    f.write('\n'.join(out))
    f.close()

if __name__ == '__main__':
    gen_docs(mask='idaapi.i')