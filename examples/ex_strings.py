import idautils

s = Strings(False)
s.setup(strtypes=Strings.STR_UNICODE | Strings.STR_C)
for i in s:
    print "%x: len=%d type=%d -> '%s'" % (i.ea, i.length, i.type, str(i))
