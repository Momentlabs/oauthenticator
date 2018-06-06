"""
Custom Authenticator to use Auth0 OAuth with JupyterHub

Derived using the Github and Google OAuthenticator implementations as examples.

The following environment variables may be used for configuration:

    AUTH0_SUBDOMAIN - The subdomain for your Auth0 account
    OAUTH_CLIENT_ID - Your client id
    OAUTH_CLIENT_SECRET - Your client secret
    OAUTH_CALLBACK_URL - Your callback handler URL

Additionally, if you are concerned about your secrets being exposed by
an env dump(I know I am!) you can set the client_secret, client_id and
oauth_callback_url directly on the config for Auth0OAuthenticator.

One instance of this could be adding the following to your jupyterhub_config.py :

  c.Auth0OAuthenticator.client_id = 'YOUR_CLIENT_ID'
  c.Auth0OAuthenticator.client_secret = 'YOUR_CLIENT_SECRET'
  c.Auth0OAuthenticator.oauth_callback_url = 'YOUR_CALLBACK_URL'

If you are using the environment variable config, all you should need to
do is define them in the environment then add the following line to 
jupyterhub_config.py :

  c.JupyterHub.authenticator_class = 'oauthenticator.auth0.Auth0OAuthenticator'

"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from traitlets import Unicode

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.handlers.login import LogoutHandler
from jupyterhub.utils import url_path_join

from .oauth2 import OAuthLoginHandler, OAuthenticator

AUTH0_SUBDOMAIN = os.getenv('AUTH0_SUBDOMAIN')

class Auth0Mixin(OAuth2Mixin):
    # subdomain = self.authenticator.auth0_subdomain
    # _OAUTH_AUTHORIZE_URL = "https://{}.auth0.com/authorize".format(subdomain)
    # _OAUTH_ACCESS_TOKEN_URL = "https://{}.auth0.com/oauth/token".format(subdomain)
    # _AUTH0_LOGOUT_URL = "https://{}.auth0.com/logout".format(subdomain)
    _OAUTH_AUTHORIZE_URL = "https://{}.auth0.com/authorize".format(AUTH0_SUBDOMAIN)
    _OAUTH_ACCESS_TOKEN_URL = "https://{}.auth0.com/oauth/token".format(AUTH0_SUBDOMAIN)
    _AUTH0_LOGOUT_URL = "https://{}.auth0.com/logout".format( AUTH0_SUBDOMAIN)

class Auth0LoginHandler(OAuthLoginHandler, Auth0Mixin):
    pass


class Auth0LogoutHandler(LogoutHandler, Auth0Mixin):

    # Go tickle the Auth0 logout page.
    # This is necessary to ensure that Auth0 cleans up its
    # browser_local cookie data to actually log the user off. Without this you get the user 
    # automaticlly logged back in without authentication. Which, at the very least, means you can't
    # change users. 
    # The returnTo argument enables Auth0 to redirect back to our normal logout.
    def get(self):

        user = self.get_current_user()
        if user:
            self.log.info("Auth0LogoutHandler: Logging out {}.".format(user))
        else:
            self.log.warning("Auth0LogoutHandler: user not found.")

        redirect_base_url = self.authenticator.client_redirect_base_url
        logout_path = '/logout' # TODO: The '/logout' piece should be obtained from the system somehow
        logout_redirect = url_path_join(redirect_base_url, logout_path ) 
        redirect_url = url_concat(self._AUTH0_LOGOUT_URL, {'returnTo': logout_redirect, 'client_id': self.authenticator.client_id})

        self.log.info("Auth0LogoutHandler: Redirecting to: {}".format(redirect_url))
        self.redirect(redirect_url, permanent=False)


class Auth0OAuthenticator(OAuthenticator):

    login_service = "Auth0"
    login_handler = Auth0LoginHandler

    client_redirect_base_url = Unicode('http://localhost',
        help="""
        Domain name used for redirecting from Auth0 (e.g. logout).
        Defaults to http://localhost
        """
    ).tag(config=True)

    auth0_subdomain = AUTH0_SUBDOMAIN
    # auth0_subdomain = Unicode('',
    #     help="""
    #     This is the subdomain to hang in front of auth0.com for the various URLs required. e.g. <auth0_domain>.auth0.com/authorize
    #     """
    # ).tag(config=True)
    
    @gen.coroutine
    def authenticate(self, handler, data=None):
        self.log.info("authenticating with Auth0")
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code':code,
            'redirect_uri': self.get_callback_url(handler)
        }
        url = "https://{}.auth0.com/oauth/token".format(self.auth0_subdomain)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Content-Type": "application/json"},
                          body=json.dumps(params)
                          )
        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest("https://{}.auth0.com/userinfo".format(self.auth0_subdomain),
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        try:
            # user_id is what Auth0 actually uses for keeping the user id, using this 
            # also allows us to leverage auth0's 'federation' of ID with the likes of
            # Google, github, facebook, linkein etc (not all of which will return a users email)
            user_id = resp_json["user_id"]
        except KeyError:
            self.log.info("Auth0Authenticator#authenticate: couldn't find user_id in response: {}".format(resp_json))
            raise

        name = user_id.replace('|', '_')
        return {
            'name': name,
            'auth_state': {
                'access_token': access_token,
                'auth0_user': resp_json,
            }
        }

    def logout_url(self, base_url):
        handler_path = url_path_join(base_url,'/auth0_logout')
        self.log.info("Auth0 returning logout handler: {0}".format(handler_path))
        return handler_path

    def get_handlers(self, app):
        handlers = []
        handlers += super().get_handlers(app)
        handlers += [(r'/auth0_logout', Auth0LogoutHandler)]
        self.log.info('Auth0 returning hanlders: {0}'.format(handlers))
        return handlers

class LocalAuth0OAuthenticator(LocalAuthenticator, Auth0OAuthenticator):

    """A version that mixes in local system user creation"""
    pass

