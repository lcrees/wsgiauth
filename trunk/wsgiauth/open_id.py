# (c) 2005 Ben Bangert
# This module is part of the Python Paste Project and is released under
# the MIT License: http://www.opensource.org/licenses/mit-license.php

'''OpenID Authentication (Consumer)

OpenID is a distributed authentication system for single sign-on originally
developed at/for LiveJournal.com.

    http://openid.net/

You can have multiple identities in the same way you can have multiple URLs.
All OpenID does is provide a way to prove that you own a URL (identity).
And it does this without passing around your password, your email address, or
anything you don't want it to. There's no profile exchange component at all:
your profiile is your identity URL, but recipients of your identity can then
learn more about you from any public, semantically interesting documents
linked thereunder (FOAF, RSS, Atom, vCARD, etc.).

This module requires installation of the Python OpenID libraries from:

    http://www.openidenabled.com/

This module is based off the consumer.py that comes with Python OpenID.
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

from util import requesturi, Redirect, NotFound, Response

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

def quoteattr(s):
    return '"%s"' % cgi.escape(s, 1)

def openided(store, **kw):
    def decorator(application):
        return OpenID(application, store, **kw)
    return decorator

_tracker = {}


class OpenID(object):

    '''Authenticates a URL against an OpenID Server.'''

    SESSION_COOKIE_NAME = '_OIDA_'

    def __init__(self, application, store, **kw):
        self.store = filestore.FileOpenIDStore(store)
        # Location to load after successful process of login        
        self.login_redirect = kw.get('login_redirect')
        #  A function which should return a username. 
        self.getuser = kw.get('getuser')
        # Redirect response
        self.redirect = kw.get('redirect', Redirect)
        # Not Found response
        self.notfound = kw.get('notfound', NotFound)
        # Generic response
        self.response = kw.get('response', self._response)
        # Session cache
        self.tracker = kw.get('tracker', _tracker)

    def __call__(self, environ, start_response):         
        environ['openid.baseurl'] = requesturi(environ, False, False)
        path = re.sub(self.prefix, '', environ['PATH_INFO'])
        environ['openid.parseduri'] = urlparse.urlparse(path)
        environ['openid.query'] = dict(cgi.parse_qsl(environ))
        path = environ['openid.parseduri'][2]
        if path == '/' or not path:
            message = 'Enter an OpenID Identifier to verify.'
            return self.response(message, environ)
        elif path == '/verify':
            return self.verify(environ)
        elif path == '/process':
            return self.process(environ)

    def verify(self, environ, start_response):
        '''Process the form submission, initating OpenID verification.
        '''
        # First, make sure that the user entered something
        openid_url = environ['openid.query'].get('openid_url')
        if not openid_url:
            message = 'Enter an OpenID Identifier to verify.'
            return self.response(message, environ)
        oidconsumer = self.getconsumer()
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
                # Find out OpenID server and get secure token.
                trust_root = environ['openid.baseurl']
                return_to = self.build_url('process')
                redirect_url = request.redirectURL(trust_root, return_to)
                return self.redirect(redirect_url)      

    def process(self, environ):
        '''Handle redirect from the OpenID server.'''
        oidconsumer, openid_url = self.getConsumer(), None
        # Verify OpenID server response
        info = oidconsumer.complete(environ['openid.query'])
        # Handle successful responses
        if info.status == consumer.SUCCESS:
            # Handle i-names
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

    def build_url(self, env, action, **query):
        '''Build a URL relative to the server base url, with the given
        query parameters added.'''
        base = urlparse.urljoin(env['openid.baseurl'], action)
        return appendArgs(base, query)

    def _response(message, environ, url=''):
        cmessage = (message, quoteattr(self.build_url(environ, 'verify')),
            quoteattr(url))
        response = Response(cmessage, template=self.template)
        return response    

    def getconsumer(environ):
        return consumer.Consumer(self.getsession(environ), self.store)

    def getsession(self, environ):
        """Return the existing session or a new session"""
        # Get value of cookie header that was sent
        cookie_str = environ.get('HTTP_COOKIE')
        if cookie_str:
            cookie_obj = SimpleCookie(cookie_str)
            sid_morsel = cookie_obj.get(self.SESSION_COOKIE_NAME, None)
            if sid_morsel is not None:
                sid = sid_morsel.value
            else:
                sid = None
        else:
            sid = None
        # If a session id was not set, create a new one
        if sid is None:
            sid = randomString(16, '0123456789abcdef')
            session = None
        else:
            session = self.tracker.get(sid)
        # If no session exists for this session ID, create one
        if session is None: session = self.tracker[sid] = {}
        session['id'] = sid
        return session