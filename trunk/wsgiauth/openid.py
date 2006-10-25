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
import cgitb
import sys
import re
from openid.consumer import consumer
from openid.oidutil import appendArgs
from util import request_uri, Redirect, NotFound

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

__all__ = ['OpenID', 'openid']

def quoteattr(s):
    return '"%s"' % cgi.escape(s, 1)


class OpenID(object):

    '''Authenticates a URL against an OpenID Server.'''

    def __init__(self, application, store_path, **kw):
        self.application = application
        store = filestore.FileOpenIDStore(store_path)
        self.data_store_path = store_path
        # Directory to store crypto data in for use with OpenID servers.
        self.oidconsumer = consumer.OpenIDConsumer(store)
        # Location for authentication process/verification        
        self.auth_prefix = kw.get('auth_prefix', '/oid')
        # Location to load after successful process of login        
        self.login_redirect = kw.get('login_redirect')
        # If true, 401 responses  turn into open ID login requirements
        self.catch_401 = kw.get('catch_401', False)
        #  A function which should return a username. 
        self.url_to_username = kw.get('url_to_username')
        # Redirect response
        self.redirect = kw.get('redirect', Redirect)
        # Not Found response
        self.notfound = kw.get('notfound', NotFound)
        # Generic response
        self.response = kw.get('response', Response)

    def __call__(self, environ, start_response):
        if environ['PATH_INFO'].startswith(self.auth_prefix):
            # Let's load everything into a request dict to pass around easier
            environ['openid.base_url'] = request_uri(environ, False, False)
            path = re.sub(self.auth_prefix, '', environ['PATH_INFO'])
            environ['openid.parsed_uri'] = urlparse.urlparse(path)
            environ['openid.query'] = dict(cgi.parse_qsl(environ))
            path = request['openid.parsed_uri'][2]
            if path == '/' or not path:
                return self.render(environ, start_response)
            elif path == '/verify':
                return self.verify(environ, start_response)
            elif path == '/process':
                return self.process(environ, start_response)
            else:
                notfound = self.notfound(environ['openid.parsed_uri'])
                return notfound(environ, start_response)
        else:
            if self.catch_401: return self.catch401(environ, start_response)
            return self.applcation(environ, start_response)

    def catch401(self, environ, start_response):
        '''Call the application and redirect if the app returns a 401.'''
        was401 = False
        def catch_response(status, headers, exc_info=None):
            if int(status.split(None, 1)) == 401:
                was401 = True
                def dummy_writer(v): pass
                return dummy_writer
            else:
                return start_response(status, headers, exc_info)
        result = self.application(environ, catch_response)
        if was401:
            redir = self.redirect(request_uri(environ, False, False))
            return redir(environ, start_response)
        return appiter

    def verify(self, environ, start_response):
        '''Process the form submission, initating OpenID verification.
        '''
        # First, make sure that the user entered something
        openid_url = environ['openid.query'].get('openid_url')
        if not openid_url:
            response = self.response(('Enter your OpenID URL.',
                quoteattr(self.build_url(environ, 'verify')),
                quoteattr(openid_url)))
            return response(environ, start_response)
        oidconsumer = self.oidconsumer
        # Then, ask the library to begin the authorization.
        # Here we find out the identity server that will verify the
        # user's identity, and get a token that allows us to
        # communicate securely with the identity server.
        status, info = oidconsumer.beginAuth(openid_url)
        # If the URL was unusable (either because of network
        # conditions, a server error, or that the response returned
        # was not an OpenID identity page), the library will return
        # an error code. Let the user know that that URL is unusable.
        if status in [consumer.HTTP_FAILURE, consumer.PARSE_ERROR]:
            if status == consumer.HTTP_FAILURE:
                fmt = 'Failed to retrieve <q>%s</q>'
            else:
                fmt = 'Could not find OpenID information in <q>%s</q>'
            message = fmt % cgi.escape(openid_url)
            response = self.response((message,
                quoteattr(self.build_url(environ, 'verify')),
                quoteattr(openid_url)))
            return response(environ, start_request)
        elif status == consumer.SUCCESS:
            # The URL was a valid identity URL. Now we construct a URL
            # that will get us to process the server response. We will
            # need the token from the beginAuth call when processing
            # the response. A cookie or a session object could be used
            # to accomplish this, but for simplicity here we just add
            # it as a query parameter of the return-to URL.
            return_to = self.build_url(environ, 'process', token=info.token)
            # Now ask the library for the URL to redirect the user to
            # his OpenID server. It is required for security that the
            # return_to URL must be under the specified trust_root. We
            # just use the base_url for this server as a trust root.
            redirect_url = oidconsumer.constructRedirect(
                info, return_to, trust_root=environ['openid.base_url'])
            # Send the redirect response
            return self.redirect(redirect_url)(environ, start_response)
        else:
            assert False, 'Not reached'

    def process(self, environ, start_response):
        '''Handle the redirect from the OpenID server.
        '''
        oidconsumer = self.oidconsumer
        # retrieve the token from the environment (in this case, the URL)
        token = environ['openid.query'].get('token', '')
        # Ask the library to check the response that the server sent
        # us.  Status is a code indicating the response type. info is
        # either None or a string containing more information about
        # the return type.
        status, info = oidconsumer.completeAuth(token, environ['openid.query'])
        openid_url = None
        if status == consumer.FAILURE and info:
            # In the case of failure, if info is non-None, it is the
            # URL that we were verifying. We include it in the error
            # message to help the user figure out what happened.
            openid_url = info
            message = 'Verification of %s failed.' % cgi.escape(openid_url)
        elif status == consumer.SUCCESS:
            # Success means that the transaction completed without
            # error. If info is None, it means that the user cancelled
            # the verification.
            if info:
                # This is a successful verification attempt. If this
                # was a real application, we would do our login,
                # comment posting, etc. here.
                openid_url = info
                if self.url_to_username:
                    username = self.url_to_username(environ, openid_url)
                else:
                    username = openid_url
                if not self.login_redirect:
                    fmt = 'You have successfully verified %s as your identity.'
                    message = fmt % cgi.escape(openid_url)
                else:
                    redirect = self.redirect(self.login_redirect)
                    return redirect(environ, start_response)
            else:
                # cancelled
                message = 'Verification cancelled'
        else:
            # Either we don't understand the code or there is no
            # openid_url included with the error. Give a generic
            # failure message. The library should supply debug
            # information in a log.
            message = 'Verification failed.'
        response = self.response((message,
                quoteattr(self.build_url(environ, 'verify')),
                quoteattr(openid_url)))
        return response(environ, start_request)

    def build_url(self, environ, action, **query):
        '''Build a URL relative to the server base_url, with the given
        query parameters added.'''
        base = urlparse.urljoin(environ['openid.base_url'], self.auth_prefix + '/' + action)
        return appendArgs(base, query)