# (c) 2005 Ben Bangert
# (c) 2005 Clark C. Evans
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php
# This code was written with funding by http://prometheusresearch.com
#
# Copyright (c) 2005 Allan Saddi <allan@saddi.com>
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

'''OpenID Authentication (Consumer)

OpenID is a distributed authentication system for single sign-on:

    http://openid.net/

You can have multiple identities in the same way you can have multiple URLs.
All OpenID does is provide a way to prove that you own a URL (identity).
And it does this without passing around your password, your email address, or
anything you don't want it to. There's no profile exchange component at all:
your profiile is your identity URL.

This module is based off the consumer.py example that comes with the Python
OpenID library.
'''

import cgi
import urlparse
import sys
from Cookie import SimpleCookie
try:
    import openid
except ImportError:
    print >> sys.stderr, '''Failed to import the OpenID library.
In order to use this example, you must either install the library
(see INSTALL in the root of the distribution) or else add the
library to python's import path (the PYTHONPATH environment variable).

For more information, see the README in the root of the library
distribution or http://www.openidenabled.com/
'''
    sys.exit(1)
from openid.store import filestore
from openid.consumer import consumer
from openid.oidutil import appendArgs
from openid.cryptutil import randomString
from yadis.discover import DiscoveryFailure
from urljr.fetchers import HTTPFetchingError
from util import geturl, getpath, Redirect, Response
from cookie import Cookie

TEMPLATE = '''<html>
  <head><title>OpenID Form</title></head>
  <body>
    <h1>%s</h1>
    <p>Enter your OpenID identity URL:</p>
      <form method="get" action=%s>
        Identity&nbsp;URL:
        <input type="text" name="openid_url" value=%s />
        <input type="submit" value="Verify" />
      </form>
    </div>
  </body>
</html>'''

__all__ = ['OpenID', 'openided']

def quote(s):
    return '"%s"' % cgi.escape(s, 1)

def openided(store, **kw):
    
    def decorator(application):
        return OpenID(application, store, **kw)
    return decorator


# Default session tracker
_tracker = {}


class OpenID(Cookie):

    def __init__(self, app, store, **kw):
        auth = OpenIDAuth(store, **kw)
        super(OpenID, self).__init__(app, auth, **kw)
        self.authorize = auth

    def initial(self, environ, start_response):
        '''Initial response to a request.'''
        def cookie_response(status, headers, exc_info=None):
            headers.append(('Set-Cookie', self.generate(environ)))
            return start_response(status, headers, exc_info)
        redirect = Redirect(environ['openid.redirect'])
        return redirect(environ, cookie_response)
        

class OpenIDAuth(object):

    '''Authenticates a URL against an OpenID Server.'''

    cname = '_OIDA_'

    def __init__(self, store, **kw):
        self.store = filestore.FileOpenIDStore(store)
        # Location to load after successful process of login        
        self.login_redirect = kw.get('login_redirect')
        #  A function which should return a username. 
        self.getuser = kw.get('getuser')        
        # Session cache
        self.tracker = kw.get('tracker', _tracker)
        # Template
        self.template = kw.get('template', TEMPLATE)

    def __call__(self, environ):
        environ['openid.baseurl'] = geturl(environ, False, False)        
        environ['openid.query'] = dict(cgi.parse_qsl(environ['QUERY_STRING']))
        path = getpath(environ)
        if path == '/verify':
            return self.verify(environ)
        elif path == '/process':
            return self.process(environ)
        else:
            message = 'Enter an OpenID Identifier to verify.'
            return self.response(message, environ)

    def verify(self, environ):
        '''Process the form submission, initating OpenID verification.'''
        # First, make sure that the user entered something
        openid_url = environ['openid.query'].get('openid_url')
        if not openid_url:
            message = 'Enter an OpenID Identifier to verify.'
            return self.response(message, environ)
        oidconsumer = self.getconsumer(environ)
        try:
            request = oidconsumer.begin(openid_url)
        except HTTPFetchingError, exc:
            message = 'Error in discovery: %s' % cgi.escape(str(exc.why))
            return self.response(message, environ, openid_url)
        except DiscoveryFailure, exc:
            message = 'Error in discovery: %s' % cgi.escape(str(exc[0]))
            return self.response(message, environ, openid_url)
        else:
            if request is None:
                fmt = 'No OpenID services found for %s'
                return self.response(fmt % cgi.escape(openid_url), environ)
            else:
                return self.redirect(environ, request)      

    def process(self, environ):
        '''Handle redirect from the OpenID server.'''
        oidconsumer, openid_url = self.getconsumer(environ), ''
        # Verify OpenID server response
        info = oidconsumer.complete(environ['openid.query'])
        # Handle successful responses
        if info.status == consumer.SUCCESS:            
            # Handle i-names
            redirecturl = self.tracker[self.getsid(environ)]['redirect']
            environ['openid.redirect'] = redirecturl
            if info.endpoint.canonicalID:                    
                return info.endpoint.canonicalID
            elif self.getuser:
                return self.getuser(environ, info.identity_url )                
            else:
                return info.identity_url
        # Handle failure to verify a URL where URL is returned.
        elif info.status == consumer.FAILURE and info.identity_url:
            openid_url = info.identity_url
            message = 'Verification of %s failed.' % cgi.escape(openid_url)
        # User cancelled verification
        elif info.status == consumer.CANCEL:            
            message = 'Verification cancelled'
        # Handle other errors
        else:            
            message = 'Verification failed.'
        return self.response(message, environ, openid_url)

    def buildurl(self, environ, action, **query):
        '''Build a URL relative to the server base url, with the given
        query parameters added.'''
        base = urlparse.urljoin(environ['openid.baseurl'], action)
        return appendArgs(base, query)

    def getconsumer(self, environ):
        return consumer.Consumer(self.getsession(environ), self.store)

    def response(self, message, env, url=''):
        hdrs = [('Set-Cookie', self.setsession(env))]
        cmessage = (message, quote(self.buildurl(env, 'verify')), quote(url))
        return Response(cmessage, template=self.template, headers=hdrs)

    def redirect(self, environ, request):
        hdrs = [('Set-Cookie', self.setsession(environ))]
        trust_root = environ['openid.baseurl']                
        return_to = self.buildurl(environ, 'process')
        redirect_url = request.redirectURL(trust_root, return_to)
        return Redirect(redirect_url, headers=hdrs)

    def getsession(self, environ):
        """Return the existing session or a new session"""
        # Get value of cookie header that was sent
        sid = self.getsid(environ)
        # If a session id was not set, create a new one
        if sid is None:
            sid = randomString(16, '0123456789abcdef')
            session = None
        else:
            session = self.tracker.get(sid)
        # If no session exists for this session ID, create one
        if session is None:
            session = self.tracker[sid] = {}
            session['redirect'] = geturl(environ)
        session['id'] = sid        
        return session

    def getsid(self, environ):
        cookie_str = environ.get('HTTP_COOKIE')        
        if cookie_str:
            cookie_obj = SimpleCookie(cookie_str)
            sid_morsel = cookie_obj.get(self.cname, None)
            if sid_morsel is not None:
                sid = sid_morsel.value
            else:
                sid = None
        else:
            sid = None
        return sid

    def setsession(self, environ):
        sid = self.getsession(environ)['id']
        return '%s=%s;' % (self.cname, sid)     