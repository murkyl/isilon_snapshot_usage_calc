# -*- coding: utf8 -*-
__date__       = "13 March 2018"
__version__    = "1.1"
__license__    = "MIT"
__status__     = "Beta"
__author__     = "Andrew Chung"
__maintainer__ = "Andrew Chung"
__email__      = "acchung@gmail.com"
__credits__    = []
__all__        = []
__copyright__ = """Copyright 2018 Andrew Chung
Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in 
the Software without restriction, including without limitation the rights to 
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
of the Software, and to permit persons to whom the Software is furnished to do 
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
SOFTWARE."""

import sys
import platform
import json
import logging
import optparse
import getpass
import re
import papi_lite

# Global logging object
l = None
# Global PAPI state dictionary
PAPI_STATE = {}

MAX_RECORDS_LIMIT = 1000
URL_PAPI_SNAPSHOTS = '1/snapshot/snapshots'


def AddParserOptions(parser):
  """Add all the options to an OptParse object
  
  Modifies the passed in OptParrse object itself"""
  parser.add_option("-u", "--user",
                    default=None,
                    help="User name for API authentication.\n"
                      "(default: <Current user>)"
                    )
  parser.add_option("-p", "--password",
                    default=None,
                    help="User password")
  parser.add_option("-s", "--server",
                    default=None,
                    help="Server and port to connect. If running on cluster you can use 127.0.0.1:8080")
  group = optparse.OptionGroup(parser, "Matching and output options")
  group.add_option("-e", "--regex",
                    action="store_true",
                    default=False,
                    help="Enable regular expression path matching instead of exact string match.")
  group.add_option("--base10",
                    action="store_true",
                    default=False,
                    help="Enable size output in base 10 units instead of base 2 SI units.")
  group.add_option("--bytes",
                    action="store_true",
                    default=False,
                    help="Output size in bytes.")
  group.add_option("--precision",
                    default=2,
                    help="Number of decimal places of precision for size output.")
  parser.add_option_group(group)
  group = optparse.OptionGroup(parser, "Logging and debug options")
  group.add_option("-l", "--log",
                    default=None,
                    help="Full path and file name for log output.  If not set"
                      "no log output to file will be generated.")
  group.add_option("--console_log",
                    action="store_true",
                    default=False,
                    help="When this flag is set, log output to console. (Default: True if no other logging enabled and quiet is False)")
  group.add_option("-q", "--quiet",
                    action="store_true",
                    default=False,
                    help="When this flag is set, do not log output to console.")
  group.add_option("--debug",
                    default=0,
                    action="count",
                    help="Add multiple debug flags to increase debug. Warning are printed automatically unless suppressed by --quiet.\n"
                      "1: Info, 2: Debug")
  parser.add_option_group(group)

def humanize_number(num, suffix='B', base=10, precision=2):
  """Changes a number into a human friendly output using units
  
  Example:
  humanize_number(1048576, base=2)
  1.00 MiB
  
  humanize_number(1048576)
  1.04 MB
  """
  num = num if num else 0
  factor = 1024.0 if base == 2 else 1000.0
  bin_mark = ''
  if num == 0:
    return "0 %s"%(suffix)
  for unit in ['', 'K', 'M', 'G', 'T', 'P' ,'E' ,'Z' , 'Y']:
    if abs(num) < factor:
      break
    num /= factor
  if unit != '' and base == 2:
    bin_mark = 'i'
  return '{0:0.{1}f} {2}{3}{4}'.format(num, precision, unit, bin_mark, suffix)
  
def calc_snap_size(snaps_list, base10=False):
  """Take a list of snapshots and returns the total size of all the snapshots in the list"""
  snap_size = 0
  for snap in snaps_list:
    snap_size = snap_size + int(snap['size'])
  return snap_size

def get_snapshots(state, path, re_enable=False):
  """Returns all snapshots on the system in an array"""
  snaps = []
  q_args = {
    'state': 'active',
    'limit': str(MAX_RECORDS_LIMIT),
  }
  response = papi_lite.rest_call(state, URL_PAPI_SNAPSHOTS, query_args=q_args)
  l.debug(response)
  if response and response[0] == 200:
    json_data = response[2]
  if re_enable:
    l.debug("Regular expression matching enabled")
    if not isinstance(path, type(re.compile("."))):
      l.debug("Compiling regular expression: %s"%path)
      pattern = re.compile(path)
    else:
      l.debug("Regular expression already compiled")
      pattern = path
    snaps = list(filter(lambda x: pattern.search(x['path']), json_data['snapshots']))
  else:
    path = path[:-1] if path.endswith('/') else path
    snaps = list(filter(lambda x: path == x['path'], json_data['snapshots']))
  return snaps
  
def main():
  global l
  global PAPI_STATE
  
  USAGE =  "usage: %prog [options] PATH_OR_REGEX..."
  DEFAULT_LOG_FORMAT = '%(asctime)s - %(module)s|%(funcName)s - %(levelname)s [%(lineno)d] %(message)s'
  
  # Create our command line parser. We use the older optparse library for compatibility on OneFS
  parser = optparse.OptionParser(usage=USAGE, version=u"%prog v" + __version__ + " (" + __date__ + ")")
  AddParserOptions(parser)
  (options, args) = parser.parse_args(sys.argv[1:])
  if (options.log is None) and (not options.quiet):
    options.console_log = True
  if len(args) == 0:
    parser.print_help()
    parser.error("incorrect number of arguments")
    
  # Setup logging
  l = logging.getLogger()
  debug_count = options.debug
  if debug_count > 1:
    l.setLevel(logging.DEBUG)
  elif debug_count > 0:
    l.setLevel(logging.INFO)
  elif not options.quiet:
    l.setLevel(logging.WARNING)
  if options.console_log:
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))
    l.addHandler(log_handler)
  if options.log:
    log_handler = logging.FileHandler(options.log)
    log_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))
    l.addHandler(log_handler)
  if (options.log is None) and (options.console_log is False):
    l.addHandler(logging.NullHandler())
  
  papi_lite.init_papi_state(PAPI_STATE)
  
  if options.server:
    PAPI_STATE['ONCLUSTER'] = False
  elif "OneFS" in platform.system():
    PAPI_STATE['ONCLUSTER'] = True
  if not PAPI_STATE['ONCLUSTER']:
    if options.user:
      PAPI_STATE['USER'] = options.user
    else:
      l.info("Using default user: %s\n"%PAPI_STATE['USER'])
      PAPI_STATE['USER'] = getpass.getuser()
    if options.password:
      PAPI_STATE['PASSWORD'] = options.password
    else:
      PAPI_STATE['PASSWORD'] = getpass.getpass()
    PAPI_STATE['SERVER'] = options.server

  # Read all the snapshots
  for path in args:
    snaps = get_snapshots(PAPI_STATE, path, options.regex)
    l.debug("Total snaps matched: %d"%len(snaps))
    l.debug(snaps)
    snap_size = calc_snap_size(snaps, options.base10)
    if not options.bytes:
      base = 10 if options.base10 else 2
      size = str(humanize_number(snap_size, base=base, precision=options.precision))
    else:
      size = str(snap_size)
    sys.stdout.write("Snapshot path: %s, size: %s"%(path, size))
    sys.stdout.write("\n")
    
# __name__ will be __main__ when run directly from the Python interpreter.
# __file__ will be None if the Python files are combined into a ZIP file and executed there
if __name__ == "__main__":
  main()