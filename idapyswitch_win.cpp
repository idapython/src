
#define PYTHON3_DLL "python3.dll"

//-------------------------------------------------------------------------
#define IDA_HKEY HKEY_CURRENT_USER
#define IDA_ADDLIB_SUBKEY L"Software\\Hex-Rays\\IDA"
#define IDA_ADDLIB_VALUE L"Python3TargetDLL"

#define PYTHON_INSTALLS_KEY L"Software\\Python"
#define PYTHON_INSTALL_PATH_SUBKEY L"InstallPath"
#define PYTHON_DISPLAY_NAME_SUBKEY L"DisplayName"
#define PYTHON_SYSVER_SUBKEY L"SysVersion"
#define PYTHON_INSTALL_PATH_DEFAULT_VALUE L""

//-------------------------------------------------------------------------
static bool open_ida_addlib_subkey(HKEY *out, REGSAM samDesired)
{
  DWORD err = RegOpenKeyExW(IDA_HKEY, IDA_ADDLIB_SUBKEY, 0, samDesired, out);
  if ( err == ERROR_SUCCESS )
    return true;
  if ( samDesired == KEY_READ )
    return false;
  // opening for write failed; create the subkeys
  err = RegCreateKeyExW(IDA_HKEY, IDA_ADDLIB_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, samDesired, NULL, out, NULL);
  return err == ERROR_SUCCESS;
}

//-------------------------------------------------------------------------
static bool read_string(
        qstring *out,
        HKEY key,
        const wchar16_t *value,
        qstring *errbuf=nullptr)
{
  DWORD type;
  DWORD size;
  if ( RegQueryValueExW(key, value, nullptr, &type, nullptr, &size) == ERROR_SUCCESS && type == REG_SZ )
  {
    bytevec_t buf;
    buf.resize(size);
    if ( RegQueryValueExW(key, value, nullptr, &type, buf.begin(), &size) == ERROR_SUCCESS && type == REG_SZ )
      return utf16_utf8(out, (wchar16_t *) buf.begin(), buf.size() / sizeof(wchar16_t));
  }
  if ( errbuf != nullptr )
    errbuf->sprnt("Couldn't query value \"%ls\"\n", value);
  return false;
}

//-------------------------------------------------------------------------
static bool write_string(
        HKEY key,
        const wchar16_t *value,
        const char *str,
        qstring *errbuf=nullptr)
{
  qwstring wstr;
  bool ok = utf8_utf16(&wstr, str)
         && RegSetValueExW(key, value, 0, REG_SZ,
                           (LPBYTE) wstr.c_str(),
                           wstr.length() * sizeof(wstr[0])) == ERROR_SUCCESS;
  if ( !ok )
    errbuf->sprnt("Couldn't write string data \"%s\" to value \"%ls\"", str, value);
  return ok;
}

//-------------------------------------------------------------------------
static bool extract_version_from_path(
        pylib_version_t *out,
        const char *_path)
{
  qstring qpath(_path);
  qpath.rtrim('\\');
  const char *path = qpath.c_str();
  const char *p = qbasename(path);
  if ( p == nullptr )
    return false;
  if ( !strnieq(p, "Python", 6) )
    return false;
  p += 6;
  if ( !qisdigit(p[0]) || !qisdigit(p[1]) )
    return false;
  out->raw = p;
  int major = p[0] - '0';
  int minor = p[1] - '0';
  int revision = 0;
  p += 2;
  if ( qisdigit(p[0]) )
  {
    revision = p[0] - '0';
    ++p;
  }
  out->major = major;
  out->minor = minor;
  out->revision = revision;
  out->modifiers = p;
  return true;
}

//-------------------------------------------------------------------------
static bool is_python3Y_dll_file_name(const char *fname)
{
  return fname != nullptr
      && strnieq(fname, "python3", 7)
      && qisdigit(fname[7])
      && strieq(&fname[8], ".dll");
}

//-------------------------------------------------------------------------
static bool probe_python_install_dir_from_dll_path(
        qstrvec_t *out_paths,
        pylib_version_t *out_version,
        const char *path,
        qstring *errbuf)
{
  char dir[QMAXPATH];
  if ( !qdirname(dir, sizeof(dir), path) )
  {
    errbuf->sprnt("Couldn't retrieve directory name from \"%s\"", path);
    return false;
  }
  extract_version_from_path(out_version, dir); // not fatal if this fails

  bool found_python3_dll = false;
  bool found_python3Y_dll = false;
  static const char dll_pattern[] = "python3*.dll";

  char pattern_path[QMAXPATH];
  qmakepath(pattern_path, sizeof(pattern_path), dir, dll_pattern, nullptr);
  qstring verbuf;
  qffblk64_t fb;
  for ( int code = qfindfirst(pattern_path, &fb, 0);
        code == 0;
        code = qfindnext(&fb) )
  {
    const char *ext = get_file_ext(fb.ff_name);
    if ( ext != nullptr && strieq(ext, "dll") )
    {
      char dll_path[QMAXPATH];
      qmakepath(dll_path, sizeof(dll_path), dir, fb.ff_name, nullptr);
      out_verb("Found: \"%s\" (version: %s)\n", dll_path, out_version->str(&verbuf));
      out_paths->push_back(dll_path);

      if ( !found_python3_dll && strieq(fb.ff_name, PYTHON3_DLL) )
        found_python3_dll = true;
      if ( !found_python3Y_dll && is_python3Y_dll_file_name(fb.ff_name) )
        found_python3Y_dll = true;
    }
  }

  if ( !found_python3_dll )
  {
    errbuf->sprnt("No \"" PYTHON3_DLL "\" file found in directory \"%s\"", dir);
    return false;
  }
  if ( !found_python3Y_dll )
  {
    errbuf->sprnt("No \"python3[0-9].dll\" file found in directory \"%s\"", dir);
    return false;
  }
  return true;
}

//-------------------------------------------------------------------------
// given a key to a path like HKLM\SOFTWARE\Python\PythonCore,
// - enumerate subkeys and their check InstallPath subkey, using the default value as the directory to the installation
// e.g.
// HKLM\SOFTWARE\Python\PythonCore\3.6\InstallPath -> (Default) = C:\Python36\
// - check for python3.dll and python3Y.dll in it and add them to 'result'
static void enum_python_key(pylib_entries_t *result, const HKEY hkey, qstring *_errbuf, qstring *_verbuf)
{
  qstring &errbuf = *_errbuf;
  qstring &verbuf = *_verbuf;
  int index = 0;
  WCHAR subkey[MAXSTR];
  qstring displayname;
  if ( read_string(&displayname, hkey, PYTHON_DISPLAY_NAME_SUBKEY) )
  {
    out("Checking installs from \"%s\"\n", displayname.c_str());
  }
  while ( true )
  {
    DWORD subkey_sz = qnumber(subkey);
    if ( RegEnumKeyExW(hkey, index++, subkey, &subkey_sz,
                       nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS )
    {
      // no more installs
      break;
    }
    HKEY ihkey;
    if ( RegOpenKeyExW(hkey, subkey, 0, KEY_READ, &ihkey) == ERROR_SUCCESS )
    {
      out_verb("Opened \"%ls\"\n", subkey);
      //opened an install. get its version from SysVersion value
      qstring sysver;
      pylib_version_t version;
      bool ok = read_string(&sysver, ihkey, PYTHON_SYSVER_SUBKEY);
      ok = ok && parse_python_version_str(&version, sysver.c_str()) && version.major >= 3;
      if ( ok )
      {
        if ( read_string(&displayname, ihkey, PYTHON_DISPLAY_NAME_SUBKEY) )
        {
          out("Checking \"%s\" (%s)\n", displayname.c_str(), sysver.c_str());
        }
        HKEY vhkey;
        if ( RegOpenKeyExW(ihkey, PYTHON_INSTALL_PATH_SUBKEY, 0, KEY_READ, &vhkey) == ERROR_SUCCESS )
        {
          qstring install_path;
          if ( read_string(&install_path, vhkey, PYTHON_INSTALL_PATH_DEFAULT_VALUE, &errbuf) )
          {
            char probe[QMAXPATH];
            qmakepath(probe, sizeof(probe), install_path.c_str(), PYTHON3_DLL, nullptr);
            pylib_version_t unused;
            qstrvec_t paths;
            if ( probe_python_install_dir_from_dll_path(
              &paths,
              &version,
              probe,
              &errbuf) )
            {
              out("Found: \"%s\" (version: %s)\n", install_path.c_str(), version.str(&verbuf));
              pylib_entry_t &e = result->get_or_create_entry_for_version(version);
              e.paths.insert(e.paths.end(), paths.begin(), paths.end());
            }
            else
            {
              out_verb("Ignoring directory \"%s\": %s\n", install_path.c_str(), errbuf.c_str());
            }
          }
          else
          {
            out_verb("Couldn't query \"%s\"'s value \"%ls\": %s\n",
              subkey,
              PYTHON_INSTALL_PATH_DEFAULT_VALUE,
              errbuf.c_str());
          }
          RegCloseKey(vhkey);
        }
        else
        {
          out_verb("Couldn't open \"%s\"\n", subkey);
        }
      }
      else
      {
        out_verb("Not a Python 3.x or no version info, skipping\n");
      }

      RegCloseKey(ihkey);
    }
  }
}
//-------------------------------------------------------------------------
void pyver_tool_t::do_find_python_libs(pylib_entries_t *result) const
{
  qstring errbuf;
  qstring verbuf;

  //
  // Enumerate:
  //   * HKEY_LOCAL_MACHINE\Software\Python\PythonCore\* versions
  //   * HKEY_CURRENT_USER\Software\Python\PythonCore\* versions
  //
  static const HKEY top_keys[] =
    {
      HKEY_LOCAL_MACHINE,
      HKEY_CURRENT_USER,
    };

  static const char * knames[] =
    {
      "HLKM",
      "HKCU",
    };
  for ( size_t i = 0; i < qnumber(top_keys); ++i )
  {
    HKEY hkey_python;
    out_verb("Searching for subkeys of \"%s\\%ls\"\n", knames[i], PYTHON_INSTALLS_KEY);
    if ( RegOpenKeyExW(top_keys[i], PYTHON_INSTALLS_KEY, 0, KEY_READ, &hkey_python) == ERROR_SUCCESS )
    {
      WCHAR subkey[MAXSTR];
      int index = 0;
      while ( true )
      {
        DWORD subkey_sz = qnumber(subkey);
        if ( RegEnumKeyExW(hkey_python, index++, subkey, &subkey_sz,
          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS )
        {
          break;
        }
        HKEY hkey;
        if ( RegOpenKeyExW(hkey_python, subkey, 0, KEY_READ, &hkey) == ERROR_SUCCESS )
        {
          out_verb("Found \"%s\\%ls\\%ls\"\n", knames[i], PYTHON_INSTALLS_KEY, subkey);
          enum_python_key(result, hkey, &errbuf, &verbuf);
          RegCloseKey(hkey);
        }
      }
      RegCloseKey(hkey_python);
    }
  }

  //
  // See if we already have one registered for IDA
  //
  {
    HKEY idahkey;
    if ( open_ida_addlib_subkey(&idahkey, KEY_READ) )
    {
      qstring existing;
      if ( read_string(&existing, idahkey, IDA_ADDLIB_VALUE) )
      {
        out_verb("Previously-used DLL: \"%s\"\n", existing.c_str());
        pylib_version_t version;
        qstrvec_t paths;
        if ( probe_python_install_dir_from_dll_path(
                     &paths,
                     &version,
                     existing.c_str(),
                     &errbuf) )
        {
          out("IDA previously used: \"%s\" (guessed version: %s). "
              "Making this the preferred version.\n",
              existing.c_str(), version.str(&verbuf));
          pylib_entry_t e(version);
          e.paths.swap(paths);
          e.preferred = true;
          result->entries.push_back(e);
        }
        else
        {
          out_verb("Ignoring directory \"%s\": %s\n",
                   existing.c_str(), errbuf.c_str());
        }
      }
      else
      {
        out_verb("\"%ls\" exists, but no \"%ls\" value found\n",
                 IDA_ADDLIB_SUBKEY, IDA_ADDLIB_VALUE);
      }
      RegCloseKey(idahkey);
    }
    else
    {
      out_verb("No \"%ls\" key found\n", IDA_ADDLIB_SUBKEY);
    }
  }
}

//-------------------------------------------------------------------------
bool pyver_tool_t::do_path_to_pylib_entry(
        pylib_entry_t *entry,
        const char *path,
        qstring *errbuf) const
{
  return probe_python_install_dir_from_dll_path(&entry->paths, &entry->version, path, errbuf);
}

#include <exehdr.h>

#include "../../ldr/pe/pe.h"
#include "../../ldr/pe/common.cpp"

//-------------------------------------------------------------------------
bool pyver_tool_t::do_apply_version(
        const pylib_entry_t &entry,
        qstring *errbuf) const
{
  HKEY idahkey;
  if ( !open_ida_addlib_subkey(&idahkey, KEY_WRITE) )
  {
    errbuf->sprnt("Couldn't open \"%ls\" key for writing\n", IDA_ADDLIB_SUBKEY);
    return false;
  }

  qstring replacement;
  bool ok = false;
  for ( const auto &path : entry.paths )
  {
    const char *candidate = qbasename(path.c_str());
    if ( is_python3Y_dll_file_name(candidate) )
    {
      replacement = candidate;
      ok = write_string(idahkey, IDA_ADDLIB_VALUE, path.c_str(), errbuf);
      break;
    }
  }
  RegCloseKey(idahkey);
  if ( !ok )
  {
    errbuf->sprnt("Couldn't find a suitable python3Y.dll file");
    return false;
  }

  // Now, let's handle sip.pyd
  out_verb("Handling sip.pyd\n");
  char path[QMAXPATH];
  qmakepath(path, sizeof(path), idadir(""), "python", "3", "PyQt5", "sip.pyd", nullptr);
  linput_t *linput = open_linput(path, /*remote=*/ false);
  if ( linput == nullptr )
  {
    errbuf->sprnt("File not found: %s", path);
    return false;
  }
  linput_janitor_t lj(linput);
  pe_loader_t pl;
  if ( !pl.read_header(linput, /*silent=*/ true)
    || pl.process_sections(linput) != 0 )
  {
    errbuf->sprnt("%s: couldn't read header, or process sections", path);
    return false;
  }

  for ( int ni = 0; ; ++ni )
  {
    peimpdir_t tmp;
    off_t off = pl.pe.impdir.rva + ni*sizeof(peimpdir_t);
    out_verb("Reading import table at %u (0x%x)\n", uint32(off), uint32(off));
    if ( !pl.vmread(linput, off, &tmp, sizeof(tmp)) )
    {
      errbuf->sprnt("%s: failed reading import table", path);
    }
    if ( tmp.dllname == 0 || tmp.looktab == 0 )
      break;

    char dll[MAXSTR];
    bool ok = true;
    pl.asciiz(linput, tmp.dllname, dll, sizeof(dll), &ok);
    if ( !ok )
      break;
    out_verb("Import table entry #%d; dll name: \"%s\"\n", ni, dll);
    if ( is_python3Y_dll_file_name(dll) )
    {
      out_verb("Found python3Y.dll: \"%s\" at offset %u (0x%x)\n",
               dll, tmp.dllname, tmp.dllname);
      FILE *fp = openM(path);
      if ( fp != nullptr )
      {
        file_janitor_t fpj(fp);
        if ( qfseek(fp, pl.map_ea(tmp.dllname), SEEK_SET) == 0 )
        {
          const size_t nbytes = replacement.size(); // we want to write the zero as well!
          if ( !args.dry_run )
          {
            if ( qfwrite(fp, replacement.c_str(), nbytes) == nbytes )
            {
              out_verb("File \"%s\" successfully patched (with \"%s\")\n", path, replacement.c_str());
            }
            else
            {
              errbuf->sprnt("Couldn't write %" FMT_Z " bytes to \"%s\"", nbytes, path);
              return false;
            }
          }
          else
          {
            out("Would write %" FMT_Z " bytes (\"%s\") to file\n",
                nbytes, replacement.c_str());
          }
        }
        else
        {
          errbuf->sprnt("Cannot seek to position %u in \"%s\"", tmp.dllname, path);
          return false;
        }
      }
      else
      {
        errbuf->sprnt("Couldn't open \"%s\" for writing", path);
        return false;
      }
      break;
    }
  }

  return true;
}
