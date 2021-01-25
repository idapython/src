#include <sys/mman.h>

#define BUILD_IDAPYSWITCH
#include "../../ldr/ar/ar.hpp"
#include "../../ldr/ar/aixar.hpp"
#include "../../ldr/ar/arcmn.cpp" // for is_ar_file
#include "../../ldr/mach-o/common.cpp"

//-------------------------------------------------------------------------
static void get_python_version(pylib_version_t *out, uint32 mask)
{
  out->revision = uint8(mask);
  out->minor = uint8(mask >> 8);
  out->major = uint8(mask >> 16);
}

//-------------------------------------------------------------------------
static uint32 get_python_version_mask(const pylib_version_t &version)
{
  return version.revision
       | version.minor << 8
       | version.major << 16;
}

//-------------------------------------------------------------------------
static bool get_pylib_entry_for_macho(
        pylib_entry_t *entry,
        const char *path,
        qstring *errbuf)
{
  linput_t *li = open_linput(path, false);
  if ( li == nullptr )
  {
    errbuf->sprnt("Failed to open file: %s", winerr(errno));
    return false;
  }
  linput_janitor_t lij(li);

  macho_file_t mfile(li);
  if ( !mfile.parse_header() )
  {
    errbuf->sprnt("Failed to parse Mach-O header");
    return false;
  }

  size_t n = 0;
  size_t nfat = mfile.get_fat_subfiles();
  if ( nfat == 0 )
  {
    if ( mfile.get_subfile_type(0) != macho_file_t::SUBFILE_MACH_64 )
    {
      errbuf->sprnt("File is not 64-bit Mach-O");
      return false;
    }
  }
  else
  {
    bool found_x64 = false;
    for ( size_t i = 0; i < nfat; i++ )
    {
      if ( mfile.get_subfile_type(i) == macho_file_t::SUBFILE_MACH_64 )
      {
        found_x64 = true;
        n = i;
        break;
      }
    }
    if ( !found_x64 )
    {
      errbuf->sprnt("No 64-bit arch found in FAT header");
      return false;
    }
  }

  if ( !mfile.set_subfile(n) )
  {
    errbuf->sprnt("Failed to parse load commands");
    return false;
  }

  struct ida_local lcid_finder_t : public macho_lc_visitor_t
  {
    pylib_entry_t *entry;
    lcid_finder_t(pylib_entry_t *_entry) : entry(_entry) {}
    virtual int visit_dylib(
        const struct dylib_command *dl,
        const char *begin,
        const char *end) override
    {
      if ( dl->cmd == LC_ID_DYLIB )
      {
        get_python_version(&entry->version, dl->dylib.current_version);
        get_python_version(&entry->compatibility_version, dl->dylib.compatibility_version);
        return 1;
      }
      return 0;
    }
  };

  lcid_finder_t finder(entry);
  if ( !mfile.visit_load_commands(finder) )
  {
    errbuf->sprnt("failed to determine libpython version: LC_ID_DYLIB not found");
    return false;
  }

  if ( entry->version.major != args.major_version )
  {
    qstring verbuf;
    errbuf->sprnt("unsupported python version %s", entry->version.str(&verbuf));
    return false;
  }

  entry->paths.push_back(path);
  return true;
}

//-------------------------------------------------------------------------
static int extract_pylib_bin(pylib_entries_t *result, const char *version_dir)
{
  struct ida_local pylib_finder_t : public file_visitor_t
  {
    pylib_entries_t *result;
    pylib_finder_t(pylib_entries_t *_result) : result(_result) {}
    virtual int visit_file(const char *_binpath) override
    {
      // macOS is absurdly dependent on symlinks. remove them to limit noise.
      char buf[PATH_MAX];
      const char *binpath = realpath(_binpath, buf);
      if ( binpath == nullptr )
      {
        out_verb("Skipping %s: realpath() failed: %s\n", _binpath, winerr(errno));
        return 0;
      }
      if ( result->path_history.find(binpath) != result->path_history.end() )
      {
        out_verb("Skipping %s: duplicate of %s\n", _binpath, binpath);
        return 0;
      }

      result->path_history.push_back(binpath);

      qstring errbuf;
      pylib_version_t dummy;
      pylib_entry_t entry(dummy);

      if ( !get_pylib_entry_for_macho(&entry, binpath, &errbuf) )
      {
        out_verb("Skipping %s: %s\n", binpath, errbuf.c_str());
        return 0;
      }

      qstring verbuf;
      out_verb("Found: \"%s\" (version: %s)\n", binpath, entry.version.str(&verbuf));
      result->entries.add_unique(entry);

      return 1;
    }
  };

  // the name of the Framework binary can vary. just be safe and examine all files.
  pylib_finder_t f(result);
  return visit_files(f, version_dir, "*");
}

//-------------------------------------------------------------------------
static void extract_pylib_versions(pylib_entries_t *result, const char *framework)
{
  struct ida_local version_visitor_t : public file_visitor_t
  {
    pylib_entries_t *result;
    version_visitor_t(pylib_entries_t *_result) : result(_result) {}
    virtual int visit_file(const char *version_dir) override
    {
      extract_pylib_bin(result, version_dir);
      return 0;
    }
  };

  // examine all Python versions in the Framework
  version_visitor_t v(result);
  char versions[QMAXPATH];
  qmakepath(versions, sizeof(versions), framework, "Versions", nullptr);
  visit_files(v, versions, "*", FA_DIREC);
}

//-------------------------------------------------------------------------
void pyver_tool_t::do_find_python_libs(pylib_entries_t *result) const
{
  // find all instances of Python.framework on the system
  static const char *system_fwks[] =
  {
    "/Library/Frameworks",
    "/System/Library/Frameworks",
    "/Library/Developer/CommandLineTools/Library/Frameworks",
    "/Applications/Xcode.app/Contents/Developer/Library/Frameworks",
    "/opt/local/Library/Frameworks",
  };

  qstrvec_t framework_dirs;
  for ( size_t i = 0; i < qnumber(system_fwks); i++ )
    framework_dirs.push_back(system_fwks[i]);

  struct ida_local homebrew_handler_t : public file_visitor_t
  {
    qstrvec_t *framework_dirs;
    homebrew_handler_t(qstrvec_t *_framework_dirs) : framework_dirs(_framework_dirs) {}
    virtual int visit_file(const char *path) override
    {
      framework_dirs->push_back(qstring(path) + "/Frameworks");
      return 0;
    }
  };

  // homebrew keeps python installations in /usr/local/opt/python@X.X/Frameworks
  homebrew_handler_t hh(&framework_dirs);
  visit_files(hh, "/usr/local/opt", "python*", FA_DIREC);

  struct ida_local python_framework_finder_t : public file_visitor_t
  {
    pylib_entries_t *result;
    python_framework_finder_t(pylib_entries_t *_result) : result(_result) {}
    virtual int visit_file(const char *framework) override
    {
      extract_pylib_versions(result, framework);
      return 0;
    }
  };

  // check for a PythonX.framework in each framework dir
  python_framework_finder_t pff(result);
  for ( size_t i = 0, n = framework_dirs.size(); i < n; i++ )
    visit_files(pff, framework_dirs[i].c_str(), "Python*.framework", FA_DIREC);
}

//-------------------------------------------------------------------------
bool pyver_tool_t::do_path_to_pylib_entry(
        pylib_entry_t *entry,
        const char *path,
        qstring *errbuf) const
{
  return get_pylib_entry_for_macho(entry, path, errbuf);
}

//-------------------------------------------------------------------------
// misc information required to patch the load command for libpython
struct python_lc_info_t
{
  uint32 off;              // offset of libpython load command
  uint32 size;             // size of libpython load command
  qstring path;            // libpython path
  pylib_version_t version; // libpython version
  bytevec_t header;        // header data: mach_header + all load commands
  uint32 headerpadsz;      // size of header, including all padded bytes
  python_lc_info_t(void) : off(0), size(0), headerpadsz(UINT_MAX) {}
};

//-------------------------------------------------------------------------
static bool get_python_lc_info(python_lc_info_t *plc, const char *path, qstring *errbuf)
{
  linput_t *li = open_linput(path, false);
  if ( li == nullptr )
  {
    errbuf->sprnt("Failed to open file: %s", winerr(errno));
    return false;
  }
  linput_janitor_t lij(li);

  // here we are assuming the target binary was built by us, which means it is a non-fat,
  // 64-bit Mach-O file that links against a PythonX.X framework, and has its header padded
  // so that we can patch the load commands without issue.
  macho_file_t mfile(li);
  if ( !mfile.parse_header() )
  {
    errbuf->sprnt("Failed to parse Mach-O header");
    return false;
  }
  if ( mfile.get_fat_subfiles() > 0 || mfile.get_subfile_type(0) != macho_file_t::SUBFILE_MACH_64 )
  {
    errbuf->sprnt("Unexpected filetype (expected 64-bit Mach-O)");
    return false;
  }
  if ( !mfile.set_subfile(0) )
  {
    errbuf->sprnt("Failed to parse load commands");
    return false;
  }

  const secvec_t &sects = mfile.get_sections();

  // find the section with the smallest fileoff. it will tell us the size of the padded header.
  for ( size_t i = 0, nsects = sects.size(); i < nsects; i++ )
  {
    const section_64 &s = sects[i];

    if ( s.size != 0
      && (s.flags & S_ZEROFILL) == 0
      && (s.flags & S_THREAD_LOCAL_ZEROFILL) == 0
      && s.offset < plc->headerpadsz )
    {
      plc->headerpadsz = s.offset;
    }
  }

  if ( plc->headerpadsz == UINT_MAX )
  {
    errbuf->sprnt("Failed to determine padded size of the Mach-O header");
    return false;
  }

  // extract the libpython load command
  struct ida_local python_lc_finder_t : public macho_lc_visitor_t
  {
    python_lc_info_t *plc;
    python_lc_finder_t(python_lc_info_t *_plc) : plc(_plc)
    {
      plc->off = sizeof(mach_header_64);
    }
    virtual int visit_any_load_command(
        const struct load_command *lc,
        const char *begin,
        const char *end) override
    {
      if ( lc->cmd == LC_LOAD_DYLIB )
      {
        const struct dylib_command *dl = (const struct dylib_command *)begin;
        const char *p = begin + dl->dylib.name.offset;
        if ( p < end )
        {
          qstring _path = qstring(p, end-p);
          const char *basename = qbasename(_path.c_str());
          if ( strneq(basename, "Python", 6) || strneq(basename, "libpython", 9) )
          {
            plc->path = _path;
            plc->size = dl->cmdsize;
            get_python_version(&plc->version, dl->dylib.current_version);
            return 1;
          }
        }
      }
      // not libpython, keep looking
      plc->off += lc->cmdsize;
      return 0;
    }
  };

  python_lc_finder_t finder(plc);
  if ( !mfile.visit_load_commands(finder) )
  {
    errbuf->sprnt("No libpython dependency found");
    return false;
  }

  mfile.get_mach_header_data(&plc->header);
  return true;
}

//-------------------------------------------------------------------------
typedef janitor_t<int> fd_janitor_t;
template <> inline fd_janitor_t::~janitor_t()
{
  qclose(resource);
}

//-------------------------------------------------------------------------
static bool do_patch(
        void *map,
        const pylib_entry_t &entry,
        const python_lc_info_t &plc,
        qstring *errbuf)
{
  const char *path = entry.paths[0].c_str();
  size_t path_len  = entry.paths[0].length();

  // validate the size of the new load command
  mach_header_64 *mheader = (mach_header_64 *)map;
  uint32 sizeofcmds = mheader->sizeofcmds;
  uint32 newcmdsize = align_up(sizeof(dylib_command) + path_len + 1, 8);

  int32 diff = newcmdsize - plc.size;
  sizeofcmds += diff;

  if ( sizeofcmds + sizeof(mach_header_64) > plc.headerpadsz )
  {
    errbuf->sprnt("Updated load commands do not fit in the Mach-O header");
    return false;
  }

  // patch the mach header
  mheader->sizeofcmds = sizeofcmds;

  // patch the libpython load command
  dylib_command *cmd = (dylib_command *)((uchar *)map + plc.off);
  cmd->cmdsize = newcmdsize;
  cmd->dylib.current_version = get_python_version_mask(entry.version);
  cmd->dylib.compatibility_version = get_python_version_mask(entry.compatibility_version);

  // write the new libpython path
  uchar *ptr = (uchar *)cmd + sizeof(dylib_command);
  memcpy(ptr, path, path_len);
  ptr += path_len;
  size_t npad = newcmdsize - (sizeof(dylib_command) + path_len);
  memset(ptr, 0, npad);
  ptr += npad;

  // copy the original load commands after libpython
  const uchar *org = plc.header.begin() + plc.off + plc.size;
  const uchar *end = plc.header.end();
  size_t norg = end - org;
  memcpy(ptr, org, norg);
  ptr += norg;

  // if the new sizeofcmds is smaller, fill excess space with 0s
  if ( diff < 0 )
    memset(ptr, 0, -diff);

  return true;
}

//-------------------------------------------------------------------------
static bool patch_python_dylib_cmd(
        const char *path,
        const pylib_entry_t &entry,
        qstring *errbuf)
{
  if ( args.dry_run )
  {
    out("Would patch: %s\n", path);
    return true;
  }

  out_verb("Patching: %s\n", path);

  python_lc_info_t plc;
  if ( !get_python_lc_info(&plc, path, errbuf) )
    return false;

  // be careful that we're not patching the wrong build of idapython
  if ( entry.version.major != plc.version.major )
  {
    errbuf->sprnt("idapython binary %s was not built against python %d", path, entry.version.major);
    return false;
  }

  int fd = qopen(path, O_RDWR);
  if ( fd < 0 )
  {
    errbuf->sprnt("Failed to open file: %s", winerr(errno));
    return false;
  }
  fd_janitor_t fdj(fd);

  qstatbuf sbuf;
  memset(&sbuf, 0, sizeof(sbuf));
  if ( qfstat(fd, &sbuf) != 0 )
  {
    errbuf->sprnt("fstat() failed: %s", winerr(errno));
    return false;
  }

  void *map = mmap(0, sbuf.qst_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if ( map == MAP_FAILED )
  {
    errbuf->sprnt("mmap() failed: %s", winerr(errno));
    return false;
  }

  bool ok = do_patch(map, entry, plc, errbuf);

  munmap(map, sbuf.qst_size);
  return ok;
}

//-------------------------------------------------------------------------
bool pyver_tool_t::do_apply_version(
        const pylib_entry_t &entry,
        qstring *errbuf) const
{
  struct ida_local patcher_t : public file_visitor_t
  {
    const pylib_entry_t &entry;
    qstring *lerrbuf;
    patcher_t(const pylib_entry_t &_entry, qstring *_errbuf) : entry(_entry), lerrbuf(_errbuf) {}
    virtual int visit_file(const char *path) override
    {
      return patch_python_dylib_cmd(path, entry, lerrbuf) ? 0 : -1;
    }
  };
  patcher_t patcher(entry, errbuf);
  return for_all_plugin_files(patcher, patcher.lerrbuf) == 0;
}
