
//-------------------------------------------------------------------------
static bool extract_version_from_libpython_filename(
        pylib_version_t *out,
        const char *p)
{
  return extract_version_from_str(out, p, "libpython", ".so");
}

//-------------------------------------------------------------------------
void pyver_tool_t::do_find_python_libs(pylib_entries_t *result) const
{
  //
  // Find all libpython3*so* present on disk
  //
  static const char lib_pattern[] = "libpython3*.so*";
  static const char *dirs[] =
  {
    "/usr/lib/x86_64-linux-gnu", // Debian/Ubuntu
    "/usr/lib64", // RedHat - FHS
#ifdef _DEBUG
    "/opt/test-python-libs"
#endif
  };

  qstring verbuf;

  for ( size_t i = 0; i < qnumber(dirs); ++i )
  {
    const char *d = dirs[i];
    out_verb("Searching for \"%s\" in \"%s\"\n", lib_pattern, d);
    {
      out_ident_inc_t iinc;
      char path[QMAXPATH];
      qmakepath(path, sizeof(path), d, lib_pattern, nullptr);
      qffblk64_t fb;
      for ( int code = qfindfirst(path, &fb, 0);
            code == 0;
            code = qfindnext(&fb) )
      {
        pylib_version_t version;
        if ( extract_version_from_libpython_filename(&version, fb.ff_name) )
        {
          qmakepath(path, sizeof(path), d, fb.ff_name, nullptr);
          out_verb("Found: \"%s\" (version: %s)\n", path, version.str(&verbuf));
          pylib_entry_t &e = result->get_or_create_entry_for_version(version);
          e.paths.push_back(path);
        }
      }
    }
  }
}

//-------------------------------------------------------------------------
bool pyver_tool_t::do_path_to_pylib_entry(
        pylib_entry_t *entry,
        const char *path,
        qstring *errbuf) const
{
  const char *fname = qbasename(path);
  const bool ok = fname != nullptr && qfileexist(path);
  if ( ok )
  {
    extract_version_from_libpython_filename(&entry->version, fname);
    entry->paths.push_back(path);
  }
  else
  {
    errbuf->sprnt("Couldn't parse file name \"%s\"", fname);
  }
  return ok;
}

#define msg out
#define warning out
AS_PRINTF(1, 2) void ask_for_feedback(const char *format, ...)
{
}
#include "../../ldr/elf/reader.cpp"

//-------------------------------------------------------------------------
static bool read_ident_and_header_and_get_dyninfo(
        dynamic_info_t *out_dyninfo,
        reader_t::dyninfo_tags_t *out_dyninfo_tags,
        reader_t &reader,
        qstring *errbuf)
{
  if ( !reader.read_ident() )
  {
    *errbuf = "Couldn't parse ELF file ident";
    return false;
  }

  if ( !reader.read_header() )
  {
    *errbuf = "Couldn't parse ELF file header";
    return false;
  }

  dynamic_linking_tables_t dlt;
  if ( reader.read_section_headers()
    && reader.sections.has_valid_dynamic_linking_tables_info() )
  {
    dlt = reader.sections.get_dynamic_linking_tables_info();
  }
  else if ( reader.read_program_headers()
         && reader.pheaders.has_valid_dynamic_linking_tables_info() )
  {
    dlt = reader.pheaders.get_dynamic_linking_tables_info();
  }
  return dlt.is_valid()
      && reader.read_dynamic_info_tags(out_dyninfo_tags, dlt)
      && reader.parse_dynamic_info(out_dyninfo, *out_dyninfo_tags);
}

//-------------------------------------------------------------------------
static bool find_libpython_dt_needed_info(
        char out_dt_needed_buf[MAXSTR],
        qoff64_t *out_dt_needed_off,
        const reader_t::dyninfo_tags_t &dyninfo_tags,
        reader_t &reader,
        const char *path,
        qstring *errbuf)
{
  static const char needed_stem[] = "libpython";
  for ( const auto &dyn : dyninfo_tags )
  {
    if ( dyn.d_tag == DT_NEEDED )
    {
      const qoff64_t off = reader.dyn_strtab.offset + dyn.d_un;
      input_status_t save_excursion(reader);
      if ( save_excursion.seek(off) == -1 )
      {
        errbuf->sprnt("Couldn't seek to offset %" FMT_64 "u in \"%s\"", off, path);
        return false;
      }
      out_dt_needed_buf[0] = '\0';
      qlread(reader.get_linput(), out_dt_needed_buf, MAXSTR);
      out_verb("DT_NEEDED at offset %" FMT_64 "u is: \"%s\"\n", off, out_dt_needed_buf);
      if ( strneq(out_dt_needed_buf, needed_stem, sizeof(needed_stem)-1) )
      {
        *out_dt_needed_off = off;
        return true;
      }
    }
  }
  errbuf->sprnt("No DT_NEEDED starting with \"%s\" found", needed_stem);
  return false;
}

//-------------------------------------------------------------------------
static bool patch_dt_needed(
        const char *path,
        const qstring &_replacement,
        qstring *errbuf)
{
  out_verb("Setting relevant DT_NEEDED of \"%s\" to \"%s\"\n", path, _replacement.c_str());
  out_ident_inc_t iinc;
  linput_t *linput = open_linput(path, /*remote=*/ false);
  if ( linput == nullptr )
  {
    errbuf->sprnt("File not found: %s", path);
    return false;
  }
  linput_janitor_t lj(linput);
  reader_t reader(linput);
  dynamic_info_t dyninfo;
  reader_t::dyninfo_tags_t dyninfo_tags;
  if ( !read_ident_and_header_and_get_dyninfo(
               &dyninfo,
               &dyninfo_tags,
               reader,
               errbuf) )
  {
    return false;
  }

  char dt_needed[MAXSTR];
  qoff64_t dt_needed_off;
  if ( !find_libpython_dt_needed_info(
               dt_needed,
               &dt_needed_off,
               dyninfo_tags,
               reader,
               path,
               errbuf) )
  {
    return false;
  }

  out_verb("Found DT_NEEDED; currently: \"%s\"\n", dt_needed);

  // count the maximum number of bytes we can store in there
  size_t room = 0;
  {
    input_status_t save_excursion(reader);
    if ( save_excursion.seek(dt_needed_off) == -1 )
    {
      errbuf->sprnt("Couldn't seek to offset %" FMT_64 "u in \"%s\"", dt_needed_off, path);
      return false;
    }

    // find the end of the current DT_NEEDED
    uint8 byte;
    const int64 filesz = qlsize(reader.get_linput());
    while ( qltell(reader.get_linput()) < filesz && reader.read_byte(&byte) == 0 )
      if ( byte == 0 )
        break;

    // then find the beginning of the next string, or the end of file
    while ( qltell(reader.get_linput()) < filesz && reader.read_byte(&byte) == 0 )
      if ( byte != 0 )
        break;
    room = qltell(reader.get_linput()) - dt_needed_off - 1;
  }

  bytevec_t replacement;
  replacement.append(_replacement.c_str(), _replacement.length() + 1);
  size_t nbytes = replacement.size();
  out_verb("We have room for %" FMT_Z " bytes, and need to write %" FMT_Z "\n",
           room, nbytes);

  // and patch
  if ( room >= nbytes )
  {
    if ( room > nbytes )
    {
      out_verb("Expanding replacement with %" FMT_Z " '\\0' bytes, to "
               "override possible previous soname that could derail "
               "later computation of available room.\n", room - nbytes);
      replacement.resize(room, 0);
      nbytes = replacement.size();
    }

    FILE *fp = openM(path);
    if ( fp != nullptr )
    {
      file_janitor_t fpj(fp);
      if ( qfseek(fp, dt_needed_off, SEEK_SET) == 0 )
      {
        if ( !args.dry_run )
        {
          // we want to write the zero as well!
          if ( qfwrite(fp, replacement.begin(), nbytes) == nbytes )
          {
            out_verb("File \"%s\" successfully patched\n", path);
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
              nbytes, replacement.begin());
        }
      }
      else
      {
        errbuf->sprnt("Cannot seek to position %" FMT_64 "u in \"%s\"", dt_needed_off, path);
        return false;
      }
    }
    else
    {
      errbuf->sprnt("Couldn't open \"%s\" for writing", path);
      return false;
    }
  }
  else
  {
    errbuf->sprnt("Replacement \"%s\" has a length of %" FMT_Z
                  " bytes, but there is only room for %" FMT_Z ""
                  " bytes in the file. Cannot proceed.\n",
                  replacement.begin(), nbytes, room);
    return false;
  }
  return true;
}

//-------------------------------------------------------------------------
bool pyver_tool_t::do_apply_version(
        const pylib_entry_t &entry,
        qstring *errbuf) const
{
  qstring soname;
  for ( const auto &path : entry.paths )
  {
    out_verb("Trying to find out DT_SONAME from file \"%s\"\n", path.c_str());
    linput_t *linput = open_linput(path.c_str(), /*remote=*/ false);
    linput_janitor_t lj(linput);
    reader_t reader(linput);
    dynamic_info_t dyninfo;
    reader_t::dyninfo_tags_t dyninfo_tags;
    qstring nonfatal_errbuf;
    if ( read_ident_and_header_and_get_dyninfo(
                 &dyninfo,
                 &dyninfo_tags,
                 reader,
                 &nonfatal_errbuf) )
    {
      for ( const auto &dyn : dyninfo_tags )
      {
        if ( dyn.d_tag == DT_SONAME )
        {
          soname = dyninfo.d_un_str(reader, dyn.d_tag, dyn.d_un);
          out_verb("Found DT_SONAME: \"%s\"\n", soname.c_str());
          break;
        }
      }
    }
    else
    {
      out_verb("%s: %s", path.c_str(), nonfatal_errbuf.c_str());
    }
    if ( !soname.empty() )
      break;
  }
  if ( soname.empty() )
  {
    *errbuf = "No SONAME found";
    return false;
  }

  // Now, do patch
  struct ida_local patcher_t : public file_visitor_t
  {
    const qstring &lsoname;
    qstring *lerrbuf;

    patcher_t(const qstring &_soname, qstring *_errbuf)
      : lsoname(_soname), lerrbuf(_errbuf) {}

    virtual int visit_file(const char *path)
    {
      return patch_dt_needed(path, lsoname, lerrbuf) ? 0 : -1;
    }
  };
  patcher_t patcher(soname, errbuf);
  return for_all_plugin_files(patcher, patcher.lerrbuf) == 0;
}

//-------------------------------------------------------------------------
static int run_command(const char *_cmd, qstring *errbuf)
{
  qstring cmd(_cmd);
  if ( args.dry_run )
    cmd.insert("echo ");
  int rc = -1;
  out_verb("Running: \"%s\"\n", cmd.c_str());
  FILE *fp = popen(cmd.c_str(), "r");
  if ( fp != nullptr )
  {
    char outbuf[MAXSTR];
    /*ssize_t nread =*/ qfread(fp, outbuf, sizeof(outbuf));
    rc = pclose(fp);
    if ( rc != 0 )
      errbuf->sprnt("Error calling \"%s\"; output is: %s", cmd.c_str(), outbuf);
  }
  else
  {
    errbuf->sprnt("Command \"%s\" couldn't be run", cmd.c_str());
  }
  return rc;
}

//-------------------------------------------------------------------------
#define SLOT_SIZE 64
static bool split_debug_expand_libpython3_dtneeded_room(
        const char *path,
        qstring *errbuf)
{
  qstring cmdline;
  char dt_needed[MAXSTR];
  {
    qstring debug_path(path);
    debug_path.append(".debug");

    char path_dir[QMAXPATH];
    if ( !qdirname(path_dir, sizeof(path_dir), path) )
    {
      errbuf->sprnt("Cannot obtain directory name for path \"%s\"", path);
      return false;
    }

    {
      char cwd[QMAXPATH];
      qgetcwd(cwd, sizeof(cwd));

      if ( qchdir(path_dir) == 0 )
      {
        out_verb("Changed directory to: \"%s\"\n", path_dir);
      }
      else
      {
        errbuf->sprnt("Cannot chdir to \"%s\"", path_dir);
        return false;
      }


      cmdline.sprnt("objcopy --only-keep-debug %s %s", qbasename(path), qbasename(debug_path.c_str()));
      if ( run_command(cmdline.c_str(), errbuf) != 0 )
        return false;

      cmdline.sprnt("strip -s -x %s", qbasename(path));
      if ( run_command(cmdline.c_str(), errbuf) != 0 )
        return false;

      cmdline.sprnt("objcopy --add-gnu-debuglink=%s %s", qbasename(debug_path.c_str()), qbasename(path));
      if ( run_command(cmdline.c_str(), errbuf) != 0 )
        return false;

      if ( qchdir(cwd) == 0 )
      {
        out_verb("Back to directory: \"%s\"\n", cwd);
      }
      else
      {
        errbuf->sprnt("Cannot chdir back to \"%s\"", cwd);
        return -1;
      }
    }

    linput_t *linput = open_linput(path, /*remote=*/ false);
    if ( linput == nullptr )
    {
      errbuf->sprnt("File not found: %s", path);
      return false;
    }
    linput_janitor_t lj(linput);
    reader_t reader(linput);
    dynamic_info_t dyninfo;
    reader_t::dyninfo_tags_t dyninfo_tags;
    if ( !read_ident_and_header_and_get_dyninfo(
                 &dyninfo,
                 &dyninfo_tags,
                 reader,
                 errbuf) )
    {
      return false;
    }

    qoff64_t dt_needed_off;
    if ( !find_libpython_dt_needed_info(
                 dt_needed,
                 &dt_needed_off,
                 dyninfo_tags,
                 reader,
                 path,
                 errbuf) )
    {
      return false;
    }
  }

  qstring replacement(dt_needed);
  replacement.resize(SLOT_SIZE, '_');

  // call patchelf to replace the DT_NEEDED with a padded one
  out_verb("Found DT_NEEDED: \"%s\"; replacing with \"%s\"\n",
           dt_needed, replacement.c_str());

  cmdline.sprnt("patchelf --replace-needed %s %s %s",
                dt_needed,
                replacement.c_str(),
                path);
  if ( run_command(cmdline.c_str(), errbuf) == 0 )
  {
    out_verb("\"%s\" command successful. Restoring the "
             "original DT_NEEDED of \"%s\"\n",
             cmdline.c_str(), dt_needed);
    if ( !patch_dt_needed(path, dt_needed, errbuf) )
      return false;
  }
  else
  {
    return false;
  }

  return true;
}
