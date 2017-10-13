
// We'll take advantage of the fact that SWiG's 'python.swg' includes
// an "unqualified" 'pymacros.swg', for us to override a SWiG define
// that will be used for generating exception text (and which I have
// found no other way to redefine). Then, we'll include the real
// 'pymacros.swg' file, as if nothing happened.
#define SWIG_DirOutFail(code, msg)        Swig::DirectorTypeMismatchException::raise(SWIG_ErrorType(code), msg " in method '$symname'")

%include <python/pymacros.swg>
