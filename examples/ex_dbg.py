from tempo import *;

def test_getmeminfo():
    L = tempo.getmeminfo()
    out = []

    # startEA endEA name sclass sbase bitness perm
    for (startEA, endEA, name, sclass, sbase, bitness, perm) in L:
        out.append("%x: %x name=<%s> sclass=<%s> sbase=%x bitness=%2x perm=%2x" % (startEA, endEA, name, sclass, sbase, bitness, perm))

    f = file(r"d:\temp\out.log", "w")
    f.write("\n".join(out))
    f.close()

    print "dumped meminfo!"


def test_getregs():
    # name flags class dtyp bit_strings bit_strings_default_mask
    L = tempo.getregs()
    out = []
    for (name, flags, cls, dtype, bit_strings, bit_strings_default_mask) in L:
        out.append("name=<%s> flags=%x class=%x dtype=%x bit_strings_mask=%x" % (name, flags, cls, dtype, bit_strings_default_mask))
        if bit_strings:
            for s in bit_strings:
                out.append("  %s" % s)

    f = file(r"d:\temp\out.log", "w")
    f.write("\n".join(out))
    f.close()

    print "dumped regs!"


