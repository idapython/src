from __future__ import print_function
import os
import sys
import shutil
import json
from glob import glob
from typing import Dict, List
from functools import lru_cache

tools_docs_path = os.path.abspath(os.path.dirname(__file__))
idapython_path = os.path.abspath(os.path.join(tools_docs_path, "..", ".."))
idasrc_path = os.path.abspath(os.path.join(idapython_path, "..", "..", ".."))

import idc

from argparse import ArgumentParser
parser = ArgumentParser()
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-m", "--modules", required=True)
parser.add_argument("-s", "--include-source-for-modules", required=True)
parser.add_argument("-x", "--exclude-modules-from-searchable-index", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")

args = parser.parse_args(idc.ARGV[1:])

args.modules = args.modules.split(",")
args.include_source_for_modules = args.include_source_for_modules.split(",")
args.exclude_modules_from_searchable_index = args.exclude_modules_from_searchable_index.split(",")

try:
# pdoc location
    pdoc_path = os.path.join(idasrc_path, "third_party", "pdoc", "pdoc-master")
    sys.path.append(pdoc_path)
    sys.path.append(tools_docs_path) # for the custom epytext
    import pdoc
except ImportError as e:
    import traceback
    idc.msg("Couldn't import module %s\n" % traceback.format_exc())
    idc.qexit(-1)

# --------------------------------------------------------------------------
def gen_docs():
    sys.path.insert(0, os.path.join(idapython_path, "tools"))

    # trash existing doc
    if os.path.isdir(args.output):
        shutil.rmtree(args.output)

    # generate new doc
    build_documentation()


# --------------------------------------------------------------------------
# This is a ripoff of pdoc's cli.py, w/ minor adjustments
def gen_lunr_search(modules: List[pdoc.Module],
                          index_docstrings: bool,
                          template_config: dict):
    """Generate index.js for search"""

    def trim_docstring(docstring):
        return re.sub(r'''
            \s+|                   # whitespace sequences
            \s+[-=~]{3,}\s+|       # title underlines
            ^[ \t]*[`~]{3,}\w*$|   # code blocks
            \s*[`#*]+\s*|          # common markdown chars
            \s*([^\w\d_>])\1\s*|   # sequences of punct of the same kind
            \s*</?\w*[^>]*>\s*     # simple HTML tags
        ''', ' ', docstring, flags=re.VERBOSE | re.MULTILINE)

    def recursive_add_to_index(dobj):
        info = {
            'ref': dobj.refname,
            'url': to_url_id(dobj.module),
        }
        if index_docstrings:
            info['doc'] = trim_docstring(dobj.docstring)
        if isinstance(dobj, pdoc.Function):
            info['func'] = 1
        index.append(info)
        for member_dobj in getattr(dobj, 'doc', {}).values():
            recursive_add_to_index(member_dobj)

    @lru_cache()
    def to_url_id(module):
        url = module.url()
        if url not in url_cache:
            url_cache[url] = len(url_cache)
        return url_cache[url]

    index: List[Dict] = []
    url_cache: Dict[str, int] = {}
    for top_module in modules:
        recursive_add_to_index(top_module)
    urls = sorted(url_cache.keys(), key=url_cache.__getitem__)

    main_path = args.output
    with open(os.path.join(main_path, 'index.js'), "w", encoding="utf-8") as f:
        f.write("URLS=")
        json.dump(urls, f, indent=0, separators=(',', ':'))
        f.write(";\nINDEX=")
        json.dump(index, f, indent=0, separators=(',', ':'))

    # Generate search.html
    with open(os.path.join(main_path, 'doc-search.html'), "w", encoding="utf-8") as f:
        rendered_template = pdoc._render_template('/search.mako', **template_config)
        f.write(rendered_template)


# --------------------------------------------------------------------------
def build_documentation():

    # import all modules
    def docfilter(obj):
        # print("OBJ: %s" % str(obj))
        if obj.name in [
                "thisown",
                "SWIG_PYTHON_LEGACY_BOOL",
        ]:
            return False
        return True

    modules = []
    for module in args.modules:
        print("Loading: %s" % module)
        modules.append(pdoc.Module(module, docfilter=docfilter))

    print("  {} module{} in the list.".format(
          len(modules), "" if len(modules) == 1 else "s"))

    pdoc.link_inheritance()

    #
    # ida_*.html
    #
    pdoc.tpl_lookup.directories.insert(0, os.path.join(tools_docs_path, "templates"))
    show_source_code = set(args.include_source_for_modules)

    def all_modules(module_collection):
        for module in module_collection:
            yield module

            yield from all_modules(module.submodules())

    for module in all_modules(modules):
        module.obj.__docformat__ = "hr_epy"

        print("Processing: %s" % module.name)
        html = module.html(
            show_source_code=module.name in show_source_code,
            search_prefix=module.name)

        path = os.path.join(args.output, module.url())
        dirname = os.path.dirname(path)
        os.makedirs(dirname, exist_ok=True)

        print("Writing: %s" % path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    #
    # doc-search.html, index.js
    #
    template_config = {}
    gen_lunr_search(
        [mod for mod in modules if mod.name not in args.exclude_modules_from_searchable_index],
        index_docstrings=True,
        template_config=pdoc._get_config(**template_config).get('lunr_search'))

    #
    # index.html
    #
    path = os.path.join(args.output, "index.html")
    class fake_module_t(object):
        def __init__(self, name, url):
            self.name = name
            self._url = url
        def url(self):
            return self._url

    index_module = fake_module_t("index", "index.html")
    html = pdoc._render_template('/index.mako', module=index_module, modules=modules)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

# --------------------------------------------------------------------------
def main():
    print("Generating documentation.....")
    gen_docs()
    print("Documentation generated!")

# --------------------------------------------------------------------------
if __name__ == "__main__":
    main()
    qexit(0)
