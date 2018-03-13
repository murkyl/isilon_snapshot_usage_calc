# -*- coding: utf8 -*-
__date__       = "13 March 2018"
__version__    = "1.0"
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

import platform
import json
import collections
import logging
import httplib
from urlparse import urlunsplit
from urlparse import urljoin
from urllib import urlencode
import ssl
import re
if "OneFS" in platform.system():
  import isi.rest

DEFAULT_API_TIMEOUT = 300
URL_PAPI_SESSION = '/session/1/session'
URL_PAPI_PLATFORM_PREFIX = '/platform/%s'

l = logging.getLogger('papi_lite')

def init_papi_state(state, oncluster=False):
  if not isinstance(state, dict):
    raise TypeError("A dictionary object is required")
  state.clear()
  state['SERVER'] = None
  state['USER'] = None
  state['PASSWORD'] = None
  state['SESSION'] = None
  state['CSRF'] = None
  state['ONCLUSTER'] = oncluster

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

def get_papi_session(server, user, password):
  """Connects to a OneFS cluster and gets a PAPI session cookie"""
  headers = {"Content-type": "application/json", "Accept": "application/json"}
  conn = httplib.HTTPSConnection(server)
  data = json.dumps({'username': user, 'password': password, 'services': ['platform']})
  try:
    conn.request('POST', URL_PAPI_SESSION, data, headers)
  except IOError as ioe:
    if ioe.errno == 61:
      raise Exception("Could not connect to the server. Check the URL including port number. Port 8080 is default.")
    raise
  except Exception as e:
    raise
  resp = conn.getresponse()
  msg = resp.read()
  l.debug('Response status code: %s'%resp.status)
  l.debug('Response: %s'%msg)
  l.debug('Headers: %s'%resp.getheaders())
  if resp.status != 200:
    try:
      err_msg = json.loads(msg)['message']
    except:
      err_msg = "Error creating PAPI session"
    raise Exception(err_msg)
  cookies = resp.getheader('set-cookie').split(';')
  l.debug('Cookies line: %s'%cookies)
  session = None
  csrf = None
  for item in cookies:
    if 'isisessid=' in item:
      m = re.search(".*(isisessid=[^\;\s]*)", item)
      if m:
        session = m.group(1).strip()
    if 'isicsrf=' in item:
      m = re.search(".*(isicsrf=[^\;]*)", item)
      if m:
        csrf = m.group(1).strip()
  l.debug('Session: %s, CSRF: %s'%(session, csrf))
  conn.close()
  return (collections.namedtuple('papi_session', ['session_id', 'csrf'])(session, csrf))

def rest_call(state, url, method=None, query_args=None, headers=None, body=None, timeout=DEFAULT_API_TIMEOUT):
  """Perform a REST call either using HTTPS or when run on an Isilon cluster,
  use the internal PAPI socket path.

  state: Opaque dictionary used to track state. This must have been initialized by the init_papi_state function one time
  url: Can be a full URL string with slashes or an array of string with no slashes
  method: HTTP method. GET, POST, PUT, DELETE, etc.
  query_args: Dictionary of key value pairs to be appended to the URL
  headers: Optional dictionary used to override HTTP headers
  body: Data to be put into the request body
  timeout: Number of seconds to wait for command to complete. Only used for the
    internal REST call"""
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
  if state['ONCLUSTER']:
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
        try:
          resume = json.loads(data[2])['resume']
          l.debug("Resume key: %s"%resume)
          query_args = {'resume': str(resume) or ''}
        except Exception as e:
          resume = False
        response_list.append(data)
      else:
        resume = False
        raise Exception("Error occurred getting data from cluster. Error code: %d"%data[0])
  else:
    l.debug("HTTPS query")
    try:
      if state['SESSION'] is None:
        state['SESSION'], state['CSRF'] = get_papi_session(state['SERVER'], state['USER'], state['PASSWORD'])
      headers["Cookie"] = state['SESSION']
      if state['CSRF']:
        headers["X-CSRF-Token"] = state['CSRF'].split('=')[1]
        headers["Referer"] = "https://" + state['SERVER']
        
      headers["Content-type"] = "application/json"
      headers["Accept"] = "application/json"
      l.debug("Sending headers: %s"%headers)
      while resume:
        url = urlunsplit(['', '', URL_PAPI_PLATFORM_PREFIX%'/'.join(remote_url), urlencode(query_args), None])
        l.debug("Method: %s"%method)
        l.debug("URL: %s"%url)
        l.debug("Headers: %s"%headers)
        # Send request over HTTPS
        conn = httplib.HTTPSConnection(state['SERVER'])
        conn.request(method, url, body, headers=headers)
        resp = conn.getresponse()
        l.debug("HTTPS Response code: %d"%resp.status)
        if resp and resp.status >= 200 and resp.status < 300:
          l.debug("HTTPS call response: %s"%resp.status)
          data = resp.read()
          l.debug("Raw data: %s"%data)
          try:
            resume_check = json.loads(data)
          except:
            resume_check = {}
          resume = resume_check.get('resume', None)
          l.debug("Resume key: %s"%resume)
          query_args = {'resume': str(resume) or ''}
          response_list.append([resp.status, resp.reason, data])
        else:
          resume = False
          raise Exception("Error occurred getting data from cluster. Error code: %d"%resp.status)
      conn.close()
    except IOError as ioe:
      if ioe.errno == 111:
        raise Exception("Could not connect to server: %s. Check address and port."%state['SERVER'])
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
