# Copyright (c) 2006 L. C. Rees.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1.  Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 2.  Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# 3.  Neither the name of the Portable Site Information Project nor the names
# of its contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import cgi
from urllib import quote


class Response(object):

    '''Generic WSGI application for HTTP responses.'''    

    _template = None    
    _status = '200 OK'
    _ctype = 'text/html'

    def __init__(self, message=None, **kw):
        # Status
        self.status = kw.get('status', self._status)
        # Response iterator        
        self.response = kw.get('response', self._response)
        # Authorization message
        self.message = message        
        # Authorization response template
        self.template = kw.get('template', self._template)
        # Header list
        self.headers = kw.get('headers', list())
        # Content type
        ctype = kw.get('content', self._ctype)
        self.headers.append(('Content-type', ctype))

    def __call__(self, environ, start_response):
        start_response(self.status, self.headers)
        return self.response(self.message or geturl(environ))

    def _response(self, message):
        '''Returns an iterator containing a message body.'''
        return [self.template % message]
    

class Redirect(Response):

    '''WSGI application for HTTP 30x redirects.'''

    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
        '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
        '</body>\n</html>'
    _status = '302 Found'

    def __call__(self, environ, start_response):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))
    

class Forbidden(Response):
    
    '''WSGI application for 403 responses.'''

    _template = 'This server could not verify that you are authorized to' \
             'access resource %s from your current location.'
    _status = '403 Forbidden'
    _ctype = 'text/plain'
        
    def __call__(self, start_response):
        start_response(self.status, self.headers)
        return self.response(self.message)


class NotFound(Forbidden):

    '''WSGI application for 404 errors.'''

    _template = 'This server could not find resource %s.'
    _status = '404 Not Found'


def extract(environ, empty=False, err=False):
    '''Extracts strings in form data and returns a dict.

    @param environ WSGI environ
    @param empty Stops on empty fields (default: Fault)
    @param err Stops on errors in fields (default: Fault)
    '''
    formdata = cgi.parse(environ['wsgi.input'], environ, empty, err)    
    # Remove single entries from lists
    for key, value in formdata.iteritems():
        if len(value) == 1: formdata[key] = value[0]
    return formdata

def geturl(environ, query=True, path=True):
    '''Rebuilds a request URL (from PEP 333).
    
    @param include_query Is QUERY_STRING included in URI (default: True)
    @param include_path Is path included in URI (default: True)
    '''    
    url = [environ['wsgi.url_scheme'] + '://']
    if environ.get('HTTP_HOST'):
        url.append(environ['HTTP_HOST'])
    else:
        url.append(environ['SERVER_NAME'])
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                url.append(':' + environ['SERVER_PORT'])
        else:
            if environ['SERVER_PORT'] != '80':
                url.append(':' + environ['SERVER_PORT'])
    if path:
        url.append(getpath(environ))
    if query and environ.get('QUERY_STRING'):
        url.append('?' + environ['QUERY_STRING'])
    return ''.join(url)

def getpath(environ):
    '''Builds a path.'''
    return ''.join([quote(environ.get('SCRIPT_NAME', '')),
        quote(environ.get('PATH_INFO', ''))])