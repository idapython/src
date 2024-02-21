
#include <Python.h>

#include <err.h>

#include "extapi.hpp"

#ifdef __NT__
#include <windows.h>
#include <psapi.h>
//-------------------------------------------------------------------------
bool ext_api_t::load(qstring *errbuf)
{
  QASSERT(30602, lib_path.empty() && lib_handle == nullptr);

  // Inspired by https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-modules-for-a-process
  HANDLE hProcess = GetCurrentProcess();
  HMODULE hMods[1024];
  DWORD cbNeeded;
  if ( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded) == 0 )
    return false;

  const void *wanted = (const void *) Py_IsInitialized;
  for ( size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
  {
    MODULEINFO module_info;
    if ( GetModuleInformation(hProcess, hMods[i], &module_info, sizeof(module_info)) )
    {
      if ( wanted >= module_info.lpBaseOfDll )
      {
        LPVOID end = (LPVOID) ((const char *) module_info.lpBaseOfDll + module_info.SizeOfImage);
        if ( wanted < end )
        {
          // found module
          lib_handle = (void *) hMods[i];
          break;
        }
      }
    }
  }

  if ( lib_handle == nullptr )
    return false;

#define BIND_SYMBOL_x(Name, fail)                                       \
  do                                                                    \
  {                                                                     \
    * (FARPROC *) &Name ## _ptr = GetProcAddress(                       \
            (HMODULE) lib_handle, TEXT(#Name));                         \
    if ( Name ## _ptr == nullptr && fail )                              \
    {                                                                   \
      errbuf->sprnt("GetProcAddress(\"%s\") failed: %s",                \
                    #Name, qstrerror(-1));                              \
      return false;                                                     \
    }                                                                   \
  } while ( 0 )

#define BIND_SYMBOL(Name)      BIND_SYMBOL_x(Name, true)
#define BIND_SYMBOL_WEAK(Name) BIND_SYMBOL_x(Name, false)

  BIND_SYMBOL(PyEval_SetTrace);
  BIND_SYMBOL(PyRun_SimpleStringFlags);
  BIND_SYMBOL(PyRun_StringFlags);
#if PY_MAJOR_VERSION < 3
  BIND_SYMBOL(Py_CompileString);
#else
  BIND_SYMBOL(Py_CompileStringExFlags);
#endif
  BIND_SYMBOL(PyFunction_New);
  BIND_SYMBOL(PyFunction_GetCode);
  BIND_SYMBOL(_PyLong_AsByteArray);
  BIND_SYMBOL_WEAK(PyEval_ThreadsInitialized);
  BIND_SYMBOL_WEAK(PyEval_InitThreads);

#undef BIND_SYMBOL

  return true;
}

//-------------------------------------------------------------------------
void ext_api_t::clear()
{
  lib_handle = nullptr;
}

#else

#include <dlfcn.h>

//-------------------------------------------------------------------------
bool ext_api_t::load(qstring *errbuf)
{
  QASSERT(30603, lib_path.empty() && lib_handle == nullptr);

  // First, let's figure out the library to load
  Dl_info dl_info;
  memset(&dl_info, 0, sizeof(dl_info));
  int rc = dladdr((void *) Py_IsInitialized, &dl_info);
  if ( rc == 0 )
  {
    *errbuf = "Cannot determine path to shared object";
    return false;
  }

  lib_path = dl_info.dli_fname;
  lib_handle = dlopen(lib_path.c_str(), RTLD_NOLOAD | RTLD_GLOBAL | RTLD_LAZY);
  if ( lib_handle == nullptr )
  {
    errbuf->sprnt("dlopen(\"%s\") failed: %s", lib_path.c_str(), qstrerror(-1));
    return false;
  }

#define BIND_SYMBOL(Name)                                               \
  do                                                                    \
  {                                                                     \
    Name ## _ptr = (Name ## _t *) dlsym(lib_handle, #Name);             \
    if ( Name ## _ptr == nullptr )                                      \
    {                                                                   \
      errbuf->sprnt("dlsym(\"%s\") failed: %s", #Name, qstrerror(-1));  \
      return false;                                                     \
    }                                                                   \
  } while ( 0 )

  BIND_SYMBOL(PyEval_SetTrace);
  BIND_SYMBOL(PyRun_SimpleStringFlags);
  BIND_SYMBOL(PyRun_StringFlags);
#if PY_MAJOR_VERSION < 3
  BIND_SYMBOL(Py_CompileString);
#else
  BIND_SYMBOL(Py_CompileStringExFlags);
#endif
  BIND_SYMBOL(PyFunction_New);
  BIND_SYMBOL(PyFunction_GetCode);
  BIND_SYMBOL(_PyLong_AsByteArray);

#undef BIND_SYMBOL

  return true;
}

//-------------------------------------------------------------------------
void ext_api_t::clear()
{
  if ( lib_handle != nullptr )
  {
    dlclose(lib_handle);
    lib_handle = nullptr;
  }
}

#endif

ext_api_t extapi;

