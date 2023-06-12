"""
summary: enumerate patched bytes

description:
  Using the API to iterate over all the places in the file,
  that were patched using IDA.
"""

import ida_bytes
import ida_idaapi

# -------------------------------------------------------------------------
class patched_bytes_visitor(object):
    def __init__(self):
        self.skip = 0
        self.patch = 0

    def __call__(self, ea, fpos, o, v, cnt=()):
        if fpos == -1:
            self.skip += 1
            print("  ea: %x o: %x v: %x...skipped" % (ea, o, v))
        else:
            self.patch += 1
            print("  ea: %x fpos: %x o: %x v: %x" % (ea, fpos, o, v))
        return 0


# -------------------------------------------------------------------------
def main():
    print("Visiting all patched bytes:")
    v = patched_bytes_visitor()
    r = ida_bytes.visit_patched_bytes(0, ida_idaapi.BADADDR, v)
    if r != 0:
        print("visit_patched_bytes() returned %d" % r)
    else:
        print("Patched: %d Skipped: %d" % (v.patch, v.skip))


# -------------------------------------------------------------------------
if __name__ == '__main__':
    main()
