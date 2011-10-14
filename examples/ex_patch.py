# -------------------------------------------------------------------------
# This is an example illustrating how to visit all patched bytes in Python
# (c) Hex-Rays

import idaapi

# -------------------------------------------------------------------------
class patched_bytes_visitor(object):
    def __init__(self):
        self.skip = 0
        self.patch = 0

    def __call__(self, ea, fpos, o, v, cnt=()):
        if fpos == -1:
            self.skip += 1
            print("  ea: %x o: %x v: %x...skipped" % (ea, fpos, o, v))
        else:
            self.patch += 1
            print("  ea: %x fpos: %x o: %x v: %x" % (ea, fpos, o, v))
        return 0


# -------------------------------------------------------------------------
def main():
    print("Visiting all patched bytes:")
    v = patched_bytes_visitor()
    r = idaapi.visit_patched_bytes(0, idaapi.BADADDR, v)
    if r != 0:
        print("visit_patched_bytes() returned %d" % r)
    else:
        print("Patched: %d Skipped: %d" % (v.patch, v.skip))


# -------------------------------------------------------------------------
if __name__ == '__main__':
    main()