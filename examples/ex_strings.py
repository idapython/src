import idautils

s = idautils.Strings(False)
s.setup(strtypes=Strings.STR_UNICODE | Strings.STR_C)
for i, v in enumerate(s):
    if v is None:
        print("Failed to retrieve string index %d" % i)
    else:
        print("%x: len=%d type=%d index=%d-> '%s'" % (v.ea, v.length, v.type, i, str(v)))
