
/*
 * This utility is meant to be used to let IDA switch between
 * installed versions of Python3.
 *
 * See the documentation placed in 'opts.epilog', near the bottom
 * of this file.
 */

#ifdef __NT__
#  include <windows.h>
#endif

#include <algorithm>

//lint -esym(1788, iinc) is referenced only by its constructor or destructor

#include <pro.h>
#include <fpro.h>
#include <prodir.h>
#include <diskio.hpp>
#include <network.hpp>

#define EXIT_CODE_FORCE_PATH_FAILED 110

#define EXIT_CODE_NO_INSTALLS 120
#define EXIT_CODE_APPLY_FAILED 121

#ifdef __LINUX__
#  define EXIT_CODE_SPLIT_DEBUG_EXPAND_DT_NEEDED_ROOM_FAILED 140
#endif

#ifdef __GNUC__ // gcc defines those macros, that are in our way
#  undef major
#  undef minor
#endif

//-------------------------------------------------------------------------
struct user_args_t
{
  qstring force_path;
  bool verbose;
  bool auto_apply;
  bool dry_run;
#ifdef __UNIX__
  bool ignore_python_config;
  uint32 major_version;
#endif
#ifdef __LINUX__
  qstring split_debug_expand_libpython3_dtneeded_room; //lint !e958 padding of 4 bytes needed to align member on a 8 byte boundary
#endif

  user_args_t()
    : verbose(false),
      auto_apply(false),
      dry_run(false)
#ifdef __UNIX__
    , ignore_python_config(false),
      major_version(3)
#endif
  {}
};
static user_args_t args;

//-------------------------------------------------------------------------
static int out_ident = 0;
struct out_ident_inc_t
{
  out_ident_inc_t() { ++out_ident; }
  ~out_ident_inc_t() { --out_ident; }
};

//-------------------------------------------------------------------------
AS_PRINTF(1, 0) int vout(const char *format, va_list va)
{
  for ( int i = 0; i < out_ident; ++i )
    printf("    ");
  return vprintf(format, va);
}

//-------------------------------------------------------------------------
AS_PRINTF(1, 2) int out(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int rc = vout(format, va);
  va_end(va);
  return rc;
}

//-------------------------------------------------------------------------
AS_PRINTF(1, 2) int out_verb(const char *format, ...)
{
  int rc = 0;
  if ( args.verbose )
  {
    out("V: ");
    va_list va;
    va_start(va, format);
    rc = vout(format, va);
    va_end(va);
  }
  return rc;
}

//-------------------------------------------------------------------------
AS_PRINTF(2, 3) void error(int exit_code, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vout(format, va);
  va_end(va);
  qexit(exit_code);
}


//-------------------------------------------------------------------------
struct pylib_version_t
{
  int major;
  int minor;
  int revision;
  qstring modifiers; //lint !e958 padding of 4 bytes needed to align member on a 8 byte boundary
  qstring raw;

  pylib_version_t(
          int _major=0,
          int _minor=0,
          int _revision=0,
          const char *_modifiers=nullptr,
          const char *_raw=nullptr)
    : major(_major),
      minor(_minor),
      revision(_revision),
      modifiers(_modifiers),
      raw(_raw) {}

  bool valid() const { return major > 0; }

  const char *str(qstring *out) const
  {
    out->sprnt("%d.%d.%d%s ('%s')",
               major, minor, revision,
               modifiers.c_str(), raw.c_str());
    return out->c_str();
  }

  DECLARE_COMPARISONS(pylib_version_t)
  {
    if ( major != r.major )
      return major - r.major;
    if ( minor != r.minor )
      return minor - r.minor;
    if ( revision != r.revision )
      return revision - r.revision;
    // when it comes to modifiers, we'll consider:
    //  - that a debug version is lesser than a non-debug one
    //  - that a version with more modifiers is "greater" than
    //    one with fewer modifiers.
    const int has_debug   = qstrstr(modifiers.c_str(), "d") != nullptr;
    const int r_has_debug = qstrstr(r.modifiers.c_str(), "d") != nullptr;
    if ( has_debug != r_has_debug )
      return r_has_debug - has_debug;
    return modifiers.length() - r.modifiers.length();
  }
};
DECLARE_TYPE_AS_MOVABLE(pylib_version_t);

//-------------------------------------------------------------------------
struct pylib_entry_t
{
  pylib_version_t version;
#ifdef __MAC__
  pylib_version_t compatibility_version; // only for OSX
#endif
#ifdef __NT__
  qstring display_name;
#endif
  qstrvec_t paths;
  bool preferred;

  pylib_entry_t(const pylib_version_t &_version)
    : version(_version), preferred(false) {}

  const char *str(qstring *out) const
  {
    qstring pbuf, vbuf;
    for ( auto const &p : paths )
    {
      if ( !pbuf.empty() )
        pbuf.append(", ", 2);
      pbuf.append(p);
    }
    out->sprnt("Version: %s; paths: %s", version.str(&vbuf), pbuf.c_str());
    if ( preferred )
      out->append(" (PREFERRED)");
    return out->c_str();
  }

  bool operator ==(const pylib_entry_t &r) const { return paths == r.paths; }
  bool operator !=(const pylib_entry_t &r) const { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(pylib_entry_t);
typedef qvector<pylib_entry_t> pylib_entry_vec_t;

//-------------------------------------------------------------------------
struct pylib_entries_t
{
  pylib_entry_vec_t entries;

  pylib_entry_t *get_entry_for_version(const pylib_version_t &version)
  {
    for ( auto &e : entries )
      if ( e.version == version )
        return &e;
    return nullptr;
  }

  pylib_entry_t &get_or_create_entry_for_version(const pylib_version_t &version)
  {
    pylib_entry_t *e = get_entry_for_version(version);
    if ( e == nullptr )
    {
      pylib_entry_t ne(version);
      entries.push_back(ne);
      e = &entries.back();
    }
    return *e;
  }
};

#ifdef __UNIX__
static void set_preferred_pylib_version(pylib_entries_t *result);
#endif

//-------------------------------------------------------------------------
struct pyver_tool_t
{
  static bool reverse_compare_entries(
          const pylib_entry_t &e0,
          const pylib_entry_t &e1)
  {
    if ( e0.preferred )
      return true;
    if ( e1.preferred )
      return false;
    int rc = e0.version.compare(e1.version);
    if ( rc > 0 )
      return true;
    return false;
  }

  bool path_to_pylib_entry(
          pylib_entry_t *out,
          const char *path,
          qstring *errbuf) const
  {
    return do_path_to_pylib_entry(out, path, errbuf);
  }

  void find_python_libs(
          pylib_entries_t *result) const
  {
    do_find_python_libs(result);

#ifdef __UNIX__
    set_preferred_pylib_version(result);
#endif

    std::sort(result->entries.begin(), result->entries.end(), reverse_compare_entries);

    qstring buf;
    if ( args.verbose )
    {
      out_ident_inc_t iinc;
      for ( auto const &e : result->entries )
        out_verb("%s\n", e.str(&buf));
    }
  }

  bool apply_version(
          const pylib_entry_t &entry,
          qstring *errbuf) const
  {
    return do_apply_version(entry, errbuf);
  }

private:
  // These three need to be implemented in different
  // ways on __NT__, __LINUX__ and __MAC__

  // Look on the filesystem (or the registry on Windows)
  // for available Python3 installations.
  void do_find_python_libs(pylib_entries_t *out) const;

  // Given a path to a .so, .dll or .dylib, try and parse the
  // Python3 version and produce an entry with it.
  bool do_path_to_pylib_entry(pylib_entry_t *entry, const char *path, qstring *errbuf) const;

  // Do patch the idapython.[so|dylib] binary (or the
  // registry on Windows) so that they refer to the right
  // Python3 version.
  bool do_apply_version(const pylib_entry_t &entry, qstring *errbuf) const;
};

//-------------------------------------------------------------------------
// Accepts:
//   "3.7"
//   "3.7.1"
//   "3.7m"
//   "3.7.1dm"

//lint -esym(528, parse_python_version_str) not referenced
static bool parse_python_version_str(pylib_version_t *out, const char *raw)
{
  int major = 0;
  int minor = 0;
  int revision = 0;
  int nchars_read;

  const char *p = raw;

  if ( qsscanf(raw, "%d.%d%n", &major, &minor, &nchars_read) != 2 )
    return false;
  p += nchars_read;

  if ( p[0] == '.' && qisdigit(p[1]) )
  {
    if ( qsscanf(p, ".%d%n", &revision, &nchars_read) != 1 )
      return false;
    p += nchars_read;
  }

  *out = pylib_version_t(major, minor, revision, p, raw);
  return true;
}

#ifdef __UNIX__
//-------------------------------------------------------------------------
static bool extract_version_from_str(
        pylib_version_t *out,
        const char *p,
        const char *stem,
        const char *end_delimiter)
{
  const size_t stemlen = qstrlen(stem);
  if ( !strneq(p, stem, stemlen) )
    return false;
  p += stemlen;
  const char *p2 = qstrstr(p, end_delimiter);
  if ( p2 == nullptr )
    p2 = tail(p);
  size_t nbytes = p2 - p;
  char raw[MAXSTR];
  if ( nbytes > sizeof(raw) - 1 )
    nbytes = sizeof(raw) - 1;
  memmove(raw, p, nbytes);
  raw[nbytes] = '\0';
  parse_python_version_str(out, raw);
  return true;
}

//-------------------------------------------------------------------------
static void set_preferred_pylib_version(pylib_entries_t *result)
{
  // If python(3)-config exists, use it to determine the preferred version
  if ( args.ignore_python_config )
    return;

  const char *config_util = args.major_version == 3 ? "python3-config" : "python-config";
  qstring cmd;
  cmd.sprnt("%s --libs", config_util);

  qstring error;
  qstring verbuf;
  FILE *fp = popen(cmd.c_str(), "r");
  if ( fp != nullptr )
  {
    char outbuf[MAXSTR];
    /*ssize_t nread =*/ qfread(fp, outbuf, sizeof(outbuf));
    int rc = pclose(fp);
    if ( rc == 0 )
    {
      pylib_version_t version;
      const char *p = qstrstr(outbuf, "-lpython");
      if ( p != nullptr
        && extract_version_from_str(&version, p, "-lpython", " ") )
      {
#ifdef __MAC__
        // python3-config output on OSX will contain modifiers, i.e. "-lpython3.7m", but when detecting pylibs on OSX
        // we extract the python version from the LC_ID_DYLIB load command, which does not contain modifiers.
        // it seems safe to ignore the modifiers on OSX, they appear to be only used for compatibility purposes.
        version.modifiers.clear();
#endif
        out_verb("Preferred version, as reported by \"%s\": %s\n", cmd.c_str(), version.str(&verbuf));
        pylib_entry_t *e = result->get_entry_for_version(version);
        if ( e != nullptr )
          e->preferred = true;
        else
          error.sprnt("\"%s\" reports preferred "
                      "version \"%s\", but no corresponding library file "
                      "was found.\n", cmd.c_str(), version.str(&verbuf));
      }
      else
      {
        error.sprnt("Error parsing \"%s\" output", cmd.c_str());
      }
    }
    else
    {
      error.sprnt("Error calling \"%s\"", cmd.c_str());
    }
  }
  else
  {
    error.sprnt("\"%s\" is not available", config_util);
  }

  if ( !error.empty() )
    out_verb("%s. Cannot determine preferred version this way.\n",
             error.c_str());
}
#endif // __UNIX__

#if defined(__LINUX__) || defined(__MAC__)
#  ifdef __LINUX__
#    define SOSFX "so"
#  else
#    define SOSFX "dylib"
#  endif

//-------------------------------------------------------------------------
struct file_visitor_t
{
  virtual int visit_file(const char *path) = 0;
};

//-------------------------------------------------------------------------
static int visit_files(
        file_visitor_t &dv,
        const char *dir,
        const char *pattern,
        int attr = 0)
{
  char path[QMAXPATH];
  qmakepath(path, sizeof(path), dir, pattern, nullptr);

  qffblk64_t fb;
  for ( int code = qfindfirst(path, &fb, attr);
        code == 0;
        code = qfindnext(&fb) )
  {
    qmakepath(path, sizeof(path), dir, fb.ff_name, nullptr);
    int ret = dv.visit_file(path);
    if ( ret != 0 )
      return ret;
  }

  return 0;
}

//-------------------------------------------------------------------------
//lint -esym(528, for_all_plugin_files) not referenced
static int for_all_plugin_files(file_visitor_t &dv, qstring *errbuf)
{
  char path[QMAXPATH];
  char found = 0;
  for ( int is_ea64 = 0; is_ea64 < 2; ++is_ea64 )
  {
    // Only patch for actually available IDAs (e.g. don't fail in std edition)
    qmakepath(path, sizeof(path), idadir(""), is_ea64 ? "ida64" : "ida", nullptr);
    if ( qfileexist(path) )
    {
      found++;
      qmakepath(path, sizeof(path), idadir(""), "plugins", is_ea64 ? "idapython64." SOSFX : "idapython." SOSFX, nullptr);
      int ret = dv.visit_file(path);
      if ( ret != 0 )
        return ret;

      qmakepath(path, sizeof(path), idadir(""), "python", args.major_version == 3 ? "3" : "2", is_ea64 ? "ida_64" : "ida_32", nullptr);
      ret = visit_files(dv, path, "_ida_*.so");
      if ( ret != 0 )
        return ret;
    }
  }
  if ( !found )
  {
    errbuf->sprnt("Nothing to patch in %s", idadir(""));
    return -1;
  }

  return 0;
}
#endif

#ifdef __LINUX__
#  include "idapyswitch_linux.cpp"
#else
#  ifdef __NT__
#    include "idapyswitch_win.cpp"
#  else
#    include "idapyswitch_mac.cpp"
#  endif
#endif

//-------------------------------------------------------------------------
static void set_verbose(const char *, void *) { args.verbose = true; }
static void set_auto_apply(const char *, void *) { args.auto_apply = true; }
static void set_dry_run(const char *, void *) { args.dry_run = true; }
static void set_force_path(const char *arg, void *) { args.force_path = arg; }
#ifdef __UNIX__
static void set_ignore_python_config(const char *, void *) { args.ignore_python_config = true; }
#endif
#ifdef __LINUX__
static void set_split_debug_expand_libpython3_dtneeded_room(const char *arg, void *)
{
  args.split_debug_expand_libpython3_dtneeded_room = arg;
}
#endif
#ifdef __MAC__
static void set_use_python2(const char *, void *) { args.major_version = 2; }
#endif

//-------------------------------------------------------------------------
static const cliopt_t _opts[] =
{
  { 'v', "verbose", "Verbose mode", set_verbose, 0 },
  { 'a', "auto-apply", "Run non-interactively; automatically apply the preferred version (if found)", set_auto_apply, 0 },
  { 'r', "dry-run", "Only report what would happen; don't do it", set_dry_run, 0 },
  { 's', "force-path",
#ifdef __LINUX__
    "Have IDAPython use the specified \"/path/to/libpython[...]so\" shared object",
#else
#  ifdef __NT__
    "Have IDAPython use the specified \"\\path\\to\\python3.dll\" DLL",
#  else
    "Have IDAPython use the specified \"/path/to/libpython[...]dylib\" dylib",
#  endif
#endif
    set_force_path,
    1
  },

#ifdef __UNIX__
  { 'k', "ignore-python-config", "Don't use python-config to find out the preferred version number", set_ignore_python_config, 0 },
#endif
#ifdef __LINUX__
  { 'x', "split-debug-and-expand-libpython3-dtneeded-room", "Expand the DT_NEEDED room to N bytes, using the local `patchelf` (needed at build-time only)", set_split_debug_expand_libpython3_dtneeded_room, 1 },
#endif
#ifdef __MAC__
  { 't', "use-python2", "Search for alternate Python2 installations, and patch the Python2 version of idapython", set_use_python2, 0 },
#endif
};

//-------------------------------------------------------------------------
static const char usage_epilog[] =
  "Switch between available installations of Python3\n"
  "\n"
  "Because Python3 does not systematically install a single,\n"
  "always-available \"python3.dll\", \"libpython3.so\" or \"python3.dylib\",\n"
  "but rather allows for multiple versions of Python3 to be\n"
  "installed in parallel on a given system, many tools\n"
  "provide a way to switch between those versions.\n"
  "\n"
  "IDA is no exception, and this tool is one such Python3 'switcher'.\n"
  "\n"
  "It can be run in 3 ways:\n"
  "\n"
  "  1) The default, interactive way\n"
  "  -------------------------------\n"
  "     > $ idapyswitch\n"
  "   will look on the filesystem for available Python3 installations,\n"
  "   present the user with a list of found versions (sorted according\n"
  "   to preferability), and let the user pick which one IDA should use.\n"
  "\n"
  "  2) The 'automatic' way\n"
  "  ----------------------\n"
  "     > $ idapyswitch --auto\n"
  "   will look on the filesystem for available Python3 installations,\n"
  "   and automatically pick the one it deemed the most preferable.\n"
  "\n"
  "  3) The 'manual' way\n"
  "  -------------------\n"
#ifdef __NT__
  "     > $ idapyswitch --force-path C:\\Python37\\python3.dll\n"
#else
#  ifdef __LINUX__
  "     > $ idapyswitch --force-path /path/to/libpython3.7dm.so.1.2\n"
#  else
  "     > $ idapyswitch --force-path /path/to/Python.framework/Versions/3.7/Python\n"
#  endif
#endif
  "   will pick the path that the user provided.\n"
  "\n"
  "Once a version is picked, this tool will do the following:\n"
  "\n"
#ifdef __NT__
  "  * place the path to the directory containing python3.dll\n"
  "    into the registry. IDA will pick it up at launch-time,\n"
  "    and add it to the list of paths that have to be looked\n"
  "    into by the DLL loader.\n"
#else
#  ifdef __LINUX__
  "  * patch 'idapython.so' and 'idapython64.so' so that they\n"
  "    have a DT_NEEDED corresponding to the DT_SONAME of the\n"
  "    library that was selected.\n"
#  else
  "  * patch 'idapython.dylib' and 'idapython64.dylib' so that\n"
  "    they refer to the right Python3 dylib.\n"
#  endif
#endif
  ;

//-------------------------------------------------------------------------
int main(int argc, const char **argv)
{
  cliopts_t opts(out);
  opts.epilog = usage_epilog;
  opts.add(_opts, qnumber(_opts));
  opts.apply(argc, argv);

  qstring errbuf;

#ifdef __LINUX__
  if ( !args.split_debug_expand_libpython3_dtneeded_room.empty() )
  {
    if ( !split_debug_expand_libpython3_dtneeded_room(
                 args.split_debug_expand_libpython3_dtneeded_room.c_str(),
                 &errbuf) )
    {
      error(EXIT_CODE_SPLIT_DEBUG_EXPAND_DT_NEEDED_ROOM_FAILED,
            "Cannot split debug/expand DT_NEEDED room: %s\n",
            errbuf.c_str());
    }
    return 0;
  }
#endif

  pyver_tool_t tool;

  if ( !args.force_path.empty() )
  {
    const char *path = args.force_path.c_str();
    pylib_version_t dummy_version;
    pylib_entry_t entry(dummy_version);
    if ( !tool.path_to_pylib_entry(&entry, path, &errbuf) )
    {
      error(EXIT_CODE_FORCE_PATH_FAILED,
            "Cannot determine python library version for \"%s\": %s\n",
            path, errbuf.c_str());
    }
    if ( !tool.apply_version(entry, &errbuf) )
    {
      qstring buf;
      error(EXIT_CODE_FORCE_PATH_FAILED,
            "Applying \"%s\" (extracted from path \"%s\") failed: %s\n",
            entry.str(&buf), path, errbuf.c_str());
    }
  }
  else
  {
    pylib_entries_t entries;
    tool.find_python_libs(&entries);

    const size_t nentries = entries.entries.size();
    if ( nentries > 0 )
    {
      qstring buf;
      const pylib_entry_t *preferred = nullptr;
      if ( args.auto_apply )
      {
        preferred = &entries.entries[0];
      }
      else
      {
        out("The following Python installations were found:\n");
        for ( size_t i = 0; i < nentries; ++i )
        {
          out_ident_inc_t iinc;
          const pylib_entry_t &e = entries.entries[i];
          out("#%" FMT_Z ": %s (%s)\n",
              i,
              e.version.str(&buf),
              !e.paths.empty() ? e.paths[0].c_str() : "<unavailable path>");
        }

        size_t picked = size_t(-1);
        while ( picked >= nentries )
        {
          out("Please pick a number between 0 and %" FMT_Z " (default: 0)\n", nentries-1);
          char numbuf[MAXSTR];
          qfgets(numbuf, sizeof(numbuf), stdin);
          qstring qnumbuf(numbuf);
          qnumbuf.rtrim('\n');
          if ( qnumbuf.empty() )
            picked = 0;
          else
            picked = qatoll(qnumbuf.c_str());
        }
        preferred = &entries.entries[picked];
      }

      out("Applying version %s\n", preferred->version.str(&buf));
      if ( !tool.apply_version(*preferred, &errbuf) )
      {
        error(EXIT_CODE_APPLY_FAILED,
              "Apply failed: %s\n",
              errbuf.c_str());
      }
    }
    else
    {
      error(EXIT_CODE_NO_INSTALLS,
            "No Python installations were found\n");
    }
  }

  return 0;
}
