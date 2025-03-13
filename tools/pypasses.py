
import sys
import logging
import re

logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger(__name__)

class CleanLoggerAdapter(logging.LoggerAdapter):

    objaddr_re = re.compile(r"(<[a-zA-Z0-9\.\s_']* at )0x[0-9a-f]*(>)")

    def process(self, msg, kwargs):
        msg = re.sub(self.objaddr_re, r"\1(snipped)\2", msg)
        return msg, kwargs

    def getChild(self, suffix):
        sub_logger = self.logger.getChild(suffix)
        return CleanLoggerAdapter(sub_logger, self.extra)

logger = CleanLoggerAdapter(logger, {})

import importlib
import ast

import os
__dir__, _ = os.path.split(__file__)
import astor_0_8_1

def parse_options():
    from argparse import ArgumentParser
    p = ArgumentParser()
    p.add_argument("-m", "--idapython-module-name", required=True)
    p.add_argument("-i", "--input", required=True)
    p.add_argument("-x", "--doxygen-xml", required=True)
    p.add_argument("-c", "--cpp-wrapper", required=True)
    p.add_argument("-r", "--pydoc-overrides", required=True)
    p.add_argument("-o", "--output", required=True)
    p.add_argument("-d", "--debug", default=False, action="store_true")
    p.add_argument("-p", "--passes", required=True)
    return p.parse_args()

opts = parse_options()
if opts.debug:
    logger.setLevel(logging.DEBUG)

with open(opts.input) as fin:
    tree = ast.parse(fin.read(), filename=opts.input)

import pypasses.doxy
setattr(opts, "dx_module", pypasses.doxy.parse(opts, logger))


for one_pass in opts.passes.split(","):
    module_name = f"pypasses.{one_pass}"
    module = importlib.import_module(module_name)
    sub_logger = logger.getChild(module_name)
    module.process(tree, opts, sub_logger)
    tree = ast.fix_missing_locations(tree)

clob = astor_0_8_1.to_source(tree)
with open(opts.output, "wb") as fout:
    fout.write(clob.encode("UTF-8"))

