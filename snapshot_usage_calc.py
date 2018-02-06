# -*- coding: utf8 -*-
__date__       = "06 February 2018"
__version__    = "1.0"
__license__    = "MIT"
__status__     = "Beta"
__author__     = "Andrew Chung"
__maintainer__ = "Andrew Chung"
__email__      = "acchung@gmail.com"
__credits__    = []
__all__        = []
__copyright__ = """Copyright 2017 Andrew Chung
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
import collections
import logging
import optparse
import getpass
import httplib
from urlparse import urlunsplit
from urlparse import urljoin
from urllib import urlencode
import ssl
import re

# Global logging object
l = None
# Flag to determine if we use internal API or actually perform HTTP request
API_ONCLUSTER = 0
# Cached user credentials for HTTP request
USER = None
PASSWORD = None
SERVER = None
SESSION = None
MAX_RECORDS_LIMIT = 1000
DEFAULT_API_TIMEOUT = 300
URL_PAPI_SESSION = '/session/1/session'
URL_PAPI_PLATFORM_PREFIX = '/platform/%s'
URL_PAPI_SNAPSHOTS = '1/snapshot/snapshots'

if "OneFS" in platform.system():
  API_ONCLUSTER = 1
  import isi.rest


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
                    default="127.0.0.1:8080",
                    help="Server and port to connect. (default: %default)")
  parser.add_option("-e", "--regex",
                    action="store_true",
                    default=False,
                    help="Enable regular expression path matching instead of exact string match.")
  parser.add_option("--base10",
                    action="store_true",
                    default=False,
                    help="Enable size output in base 10 units instead of base 2 SI units.")
  parser.add_option("--bytes",
                    action="store_true",
                    default=False,
                    help="Output size in bytes.")
  parser.add_option("--precision",
                    default=2,
                    help="Number of decimal places of precision for size output.")
  parser.add_option("-l", "--log",
                    default=None,
                    help="Full path and file name for log output.  If not set"
                      "no log output to file will be generated.")
  parser.add_option("--console_log",
                    action="store_true",
                    default=False,
                    help="When this flag is set, log output to console. (Default: True if no other logging enabled and quiet is False)")
  parser.add_option("-q", "--quiet",
                    action="store_true",
                    default=False,
                    help="When this flag is set, do not log output to console.")
  parser.add_option("--debug",
                    default=0,
                    action="count",
                    help="Add multiple debug flags to increase debug. Warning are printed automatically unless suppressed by --quiet.\n"
                      "1: Info, 2: Debug")

def convert(data):
  """Changes any unicode strings in the input data to utf-8 strings. This does
  recursively go through the data structure."""
  if isinstance(data, basestring):
    return str(data)
  elif isinstance(data, collections.Mapping):
    return dict(map(convert, data.iteritems()))
  elif isinstance(data, collections.Iterable):
    return type(data)(map(convert, data))
  else:
    return data

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
  
def get_papi_session(server, user, password):
  """Connects to a OneFS cluster and gets a PAPI session cookie"""
  headers = {"Content-type": "application/json", "Accept": "application/json"}
  conn = httplib.HTTPSConnection(server)
  data = json.dumps({'username': user, 'password': password, 'services': ['platform']})
  try:
    conn.request('POST', URL_PAPI_SESSION, data, headers)
  except IOError as ioe:
    if ioe.errno == 61:
      l.critical("Could not connect to the server. Check the URL including port number. Port 8080 is default.")
      sys.exit(2)
  except Exception as e:
    l.exception(e)
    sys.exit(3)
  resp = conn.getresponse()
  l.debug(resp.read())
  l.debug(resp.getheaders())
  cookie = resp.getheader('set-cookie')
  conn.close()
  return (cookie.split(';')[0])

def rest_call(url, method=None, query_args=None, headers=None, body=None, timeout=DEFAULT_API_TIMEOUT):
  """Perform a REST call either using HTTPS or when run on an Isilon cluster,
  use the internal PAPI socket path.
  
  url: Can be a full URL string with slashes or an array of string with no slashes
  method: HTTP method. GET, POST, PUT, DELETE, etc.
  query_args: Dictionary of key value pairs to be appended to the URL
  headers: Optional dictionary used to override HTTP headers
  body: Data to be put into the request body
  timeout: Number of seconds to wait for command to complete. Only used for the
    internal REST call"""
  global API_ONCLUSTER
  global USER
  global PASSWORD
  global SESSION
  global SERVER
  
  resume = True
  response_list = []
  method = 'GET' if not method else method
  query_args = {} if not query_args else convert(query_args)
  headers = {} if not headers else headers
  body = '' if not body else body
  remote_url = url
  l.debug("REST Call params: Method: %s / Query Args: %s / URL: %s"%(method, json.dumps(query_args), remote_url))
  if isinstance(url, (unicode, str)):
    remote_url = url.split('/')
  if API_ONCLUSTER:
    l.debug("On cluster query")
    while resume:
      data = isi.rest.send_rest_request(
        socket_path = isi.rest.PAPI_SOCKET_PATH,
        method = method,
        uri = remote_url,
        query_args = query_args,
        headers = headers,
        body = body,
        timeout = timeout)
      if data and data[0] >= 200 and data[0] < 300:
        l.debug("REST call response: %s"%data[0])
        resume = json.loads(data[2])['resume']
        l.debug("Resume key: %s"%resume)
        query_args = {'resume': str(resume) or ''}
        response_list.append(data)
      else:
        resume = False
        raise Exception("Error occurred getting data from cluster. Error code: %d"%data[0])
  else:
    l.debug("HTTPS query")
    try:
      if SESSION is None:
        SESSION = get_papi_session(SERVER, USER, PASSWORD)
      headers["Cookie"] = SESSION
      headers["Content-type"] = "application/json"
      headers["Accept"] = "application/json"
      while resume:
        url = urlunsplit(['', '', URL_PAPI_PLATFORM_PREFIX%'/'.join(remote_url), urlencode(query_args), None])
        l.debug("Method: %s"%method)
        l.debug("URL: %s"%url)
        l.debug("Headers: %s"%headers)
        # Send request over HTTPS
        conn = httplib.HTTPSConnection(SERVER)
        conn.request(method, url, body, headers=headers)
        resp = conn.getresponse()
        l.debug("HTTPS Response code: %d"%resp.status)
        if resp and resp.status >= 200 and resp.status < 300:
          l.debug("HTTPS call response: %s"%resp.status)
          data = resp.read()
          resume = json.loads(data)['resume']
          l.debug("Resume key: %s"%resume)
          query_args = {'resume': str(resume) or ''}
          response_list.append([resp.status, resp.reason, data])
        else:
          resume = False
          raise Exception("Error occurred getting data from cluster. Error code: %d"%resp.status)
      conn.close()
    except IOError as ioe:
      if ioe.errno == 111:
        raise Exception("Could not connect to server: %s. Check address and port."%SERVER)
  # Combine multiple responses into 1
  response = response_list[0]
  try:
    json_data = json.loads(response[2])
  except:
    json_data = ''
  if len(response_list) > 1:
    keys = json_data.keys()
    keys.remove('total')
    keys.remove('resume')
    if len(keys) > 1:
      raise Exception("More keys remaining in REST call response than we expected: %s"%keys)
    key = keys[0]
    for i in range(1, len(response_list)):
      json_data[key] = json_data[key] + json.loads(response_list[i][2])[key]
  return (response[0], response[1], json_data)

def calc_snap_size(snaps_list, base10=False):
  """Take a list of snapshots and returns the total size of all the snapshots in the list"""
  snap_size = 0
  for snap in snaps_list:
    snap_size = snap_size + int(snap['size'])
  return snap_size

def get_snapshots(path, re_enable=False):
  """Returns all snapshots on the system in an array"""
  snaps = []
  q_args = {
    'state': 'active',
    'limit': str(MAX_RECORDS_LIMIT),
  }
  response = rest_call(URL_PAPI_SNAPSHOTS, query_args=q_args)
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
  global USER
  global PASSWORD
  global SERVER
  global API_ONCLUSTER
  
  USAGE =  "usage: %prog [options]"
  DEFAULT_LOG_FORMAT = '%(asctime)s - %(module)s|%(funcName)s - %(levelname)s [%(lineno)d] %(message)s'
  
  # Create our command line parser. We use the older optparse library for compatibility on OneFS
  parser = optparse.OptionParser(usage=USAGE, version=u"%prog v" + __version__ + " (" + __date__ + ")")
  AddParserOptions(parser)
  (options, args) = parser.parse_args(sys.argv[1:])
  if (options.log is None) and (not options.quiet):
    options.console_log = True
    
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
  
  if options.user:
    API_ONCLUSTER = 0
  if not API_ONCLUSTER:
    if options.user:
      USER = options.user
    else:
      l.info("Using default user: %s\n"%USER)
      USER = getpass.getuser()
    if options.password:
      PASSWORD = options.password
    else:
      PASSWORD = getpass.getpass()
    SERVER = options.server

  # Read all the snapshots
  for path in args:
    snaps = get_snapshots(path, options.regex)
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