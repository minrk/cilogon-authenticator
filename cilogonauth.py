"""CILogon OAuthAuthenticator for JupyterHub"""

import os
from urllib.parse import parse_qs

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

from oauthlib.oauth1 import SIGNATURE_RSA, SIGNATURE_TYPE_QUERY, Client as OAuthClient

from tornado import gen, web
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPError
from tornado.httputil import url_concat

# re-use GitHubOAuthHandler for callback, since it's actually generic
from oauthenticator import GitHubOAuthHandler

from jupyterhub.auth import Authenticator
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.utils import url_path_join as ujoin

from traitlets import Unicode, Instance


class CILogonHandler(BaseHandler):
    """OAuth handler for redirecting to """
    
    @gen.coroutine
    def get(self):
        token = yield self.authenticator.get_oauth_token()
        self.redirect(url_concat(self.authenticator.authorization_url,
            {'oauth_token': token}))


class CILogonOAuthenticator(Authenticator):
    
    login_service = "CILogon"
    
    authorization_url = "https://cilogon.org/delegate"
    oauth_url = "https://cilogon.org/oauth"
    
    client_id = Unicode(config=True)
    def _client_id_default(self):
        return os.getenv('CILOGON_CLIENT_ID')
    callback_url = Unicode(config=True)
    def _callback_url_default(self):
        return os.getenv('CILOGON_CALLBACK_URL')
    
    rsa_key_path = Unicode(config=True)
    def _rsa_key_path_default(self):
        return os.getenv('CILOGON_RSA_KEY_PATH') or 'oauth-privkey.pem'
    
    rsa_key = Unicode()
    def _rsa_key_default(self):
        with open(self.rsa_key_path) as f:
            return f.read()
    
    certreq_path = Unicode(config=True)
    def _certreq_path_default(self):
        return os.getenv('CILOGON_CERTREQ_PATH') or 'oauth-certreq.csr'
    
    certreq = Unicode()
    def _certreq_default(self):
        # read certreq. CILogon can't handle standard BEGIN/END lines, so strip them
        lines = []
        with open(self.certreq_path) as f:
            for line in f:
                if not line.isspace() and '----' not in line:
                    lines.append(line)
        return ''.join(lines)

    def login_url(self, base_url):
        return ujoin(base_url, 'oauth_login')
    
    def get_handlers(self, app):
        return [
            (r'/oauth_login', CILogonHandler),
            (r'/oauth_callback', GitHubOAuthHandler),
        ]
    
    oauth_client = Instance(OAuthClient)
    def _oauth_client_default(self):
        return OAuthClient(
            self.client_id,
            rsa_key=self.rsa_key,
            signature_method=SIGNATURE_RSA,
            signature_type=SIGNATURE_TYPE_QUERY,
        )
    
    client = Instance(AsyncHTTPClient, args=())
    
    @gen.coroutine
    def get_oauth_token(self):
        """Get the temporary OAuth token"""
        uri = url_concat(ujoin(self.oauth_url, "initiate"), {
            'oauth_callback': self.callback_url,
            'certreq': self.certreq,
        })
        uri, _, _ = self.oauth_client.sign(uri)
        req = HTTPRequest(uri)
        # FIXME: handle failure (CILogon replies with 200 on failure)
        resp = yield self.client.fetch(req)
        reply = resp.body.decode('utf8', 'replace')
        credentials = parse_qs(reply)
        return credentials['oauth_token'][0]
    
    @gen.coroutine
    def get_user_token(self, token, verifier):
        """Get a user token from an oauth callback parameters"""
        uri = url_concat(ujoin(self.oauth_url, 'token'), {
            'oauth_token': token,
            'oauth_verifier': verifier,
        })
        uri, _, _ = self.oauth_client.sign(uri)
        resp = yield self.client.fetch(uri)
        # FIXME: handle failure
        reply = resp.body.decode('utf8', 'replace')
        return parse_qs(reply)['oauth_token'][0]
    
    @gen.coroutine
    def username_from_token(self, token):
        """Turn a user token into a username"""
        uri = url_concat(ujoin(self.oauth_url, 'getcert'), {
            'oauth_token': token,
        })
        uri, _, _ = self.oauth_client.sign(uri)
        resp = yield self.client.fetch(uri)
        # FIXME: handle failure
        reply = resp.body.decode('utf8', 'replace')
        _, cert_txt = reply.split('\n', 1)
        
        cert = load_certificate(FILETYPE_PEM, cert_txt)
        username = None
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name().decode('ascii', 'replace') == 'subjectAltName':
                data = ext.get_data()
                username = data[4:].decode('utf8').lower()
                # workaround notebook bug not handling @
                username = username.replace('@', '.')
                return username
    
    @gen.coroutine
    def authenticate(self, handler):
        """Called on the OAuth callback"""
        token = yield self.get_user_token(
            handler.get_argument('oauth_token'),
            handler.get_argument('oauth_verifier'),
        )
        username = yield self.username_from_token(token)
        if not username:
            return
        if not self.check_whitelist(username):
            self.log.warn("Rejecting user not in whitelist: %s", username)
            return
        return username
