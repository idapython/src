
ifdef __NT__
  EA32_TARGET:=simple_appcall_win32.exe
  EA64_TARGET:=simple_appcall_win64.exe
else
  ifdef __LINUX__
    EA32_TARGET:=simple_appcall_linux32
    EA64_TARGET:=simple_appcall_linux64
  else
    $(error Not implemented for OSX)
  endif
endif

all: $(EA32_TARGET) $(EA64_TARGET)

simple_appcall_win32.exe: simple_appcall_win32.obj
	C:/PROGRA~2/MIB055~1/2017/PROFES~1/VC/Tools/MSVC/1415~1.267/bin/HostX86/x86/link.exe \
		/LIBPATH:C:/PROGRA~2/MIB055~1/2017/PROFES~1/VC/Tools/MSVC/1415~1.267/lib/x86 \
		/LIBPATH:C:/PROGRA~2/WI3CF2~1/10/Lib/100171~1.0/ucrt/x86 \
		/LIBPATH:C:/idasrc/THIRD_~1/mssdk/8.1/Lib/x86 \
		/OUT:$@ $<

simple_appcall_win32.obj: simple_appcall.c
	C:/PROGRA~2/MIB055~1/2017/PROFES~1/VC/Tools/MSVC/1415~1.267/bin/HostX86/x86/cl.exe \
		/IC:/PROGRA~2/MIB055~1/2017/PROFES~1/VC/Tools/MSVC/1415~1.267/Include \
		/IC:/PROGRA~2/WI3CF2~1/10/Include/100171~1.0/ucrt \
		/Zi /D__NT__ /DNDEBUG /DWIN32 /D_CONSOLE /D__VC__ /c /MD $< /Fo$@

simple_appcall_win64.exe: simple_appcall_win64.obj
	C:/PROGRA~2/MIB055~1/2017/PROFES~1/VC/Tools/MSVC/1415~1.267/bin/HostX86/x86/link.exe \
		/LIBPATH:C:/PROGRA~2/MIB055~1/2017/PROFES~1/VC/Tools/MSVC/1415~1.267/lib/x64 \
		/LIBPATH:C:/PROGRA~2/WI3CF2~1/10/Lib/100171~1.0/ucrt/x64 \
		/LIBPATH:C:/idasrc/THIRD_~1/mssdk/8.1/Lib/x64 \
		/OUT:$@ $<

simple_appcall_win64.obj: simple_appcall.c
	C:/PROGRA~2/MIB055~1/2017/PROFES~1/VC/Tools/MSVC/1415~1.267/bin/HostX64/x64/cl.exe \
		/IC:/PROGRA~2/MIB055~1/2017/PROFES~1/VC/Tools/MSVC/1415~1.267/Include \
		/IC:/PROGRA~2/WI3CF2~1/10/Include/100171~1.0/ucrt \
		/Zi /D__NT__ /DNDEBUG /DWIN32 /D_CONSOLE /D__VC__ /c /MD $< /Fo$@


simple_appcall_linux32: simple_appcall.c
	gcc -m32 -o $@ $<

simple_appcall_linux64: simple_appcall.c
	gcc -m64 -o $@ $<
