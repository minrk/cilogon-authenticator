from urllib.parse import parse_qs

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

import requests
from requests_oauthlib import OAuth1
from oauthlib.oauth1 import SIGNATURE_RSA, SIGNATURE_TYPE_QUERY

from tornado import gen, web
from tornado.httpclient import AsyncHTTPClient
from tornado.httputil import url_concat

from oauthenticator import GitHubOAuthHandler

from jupyterhub.auth import Authenticator
from jupyterhub.handlers.base import BaseHandler
from jupyterhub.utils import url_path_join


client_key = open('client_id').read()
rsa_key = open("oauth-privkey.pem").read()
queryoauth = OAuth1(client_key, signature_method=SIGNATURE_RSA,
                    rsa_key=rsa_key, signature_type=SIGNATURE_TYPE_QUERY)

service_url = "https://cilogon.org"
oauth_url = url_path_join(service_url, "oauth")

certreq = open('oauth-certreq.csr').read()
certreq = '\n'.join(line for line in certreq.splitlines() if '-----' not in line)
r = requests.get("https://cilogon.org/oauth/initiate", auth=queryoauth,
        params=dict(oauth_callback="https://localhost:8000/hub/oauth_callback",
                       certreq=certreq, certlifetime=60))
r.raise_for_status()
credentials = parse_qs(r.text)

resource_owner_key = credentials.get('oauth_token')[0]
resource_owner_secret = credentials.get('oauth_token_secret')[0]

class CILogonHandler(BaseHandler):
    _OAUTH_AUTHORIZE_URL = 'https://cilogon.org/delegate'
    _OAUTH_REQUEST_TOKEN_URL = 'https://cilogon.org/oauth/initiate'
    _OAUTH_ACCESS_TOKEN_URL = 'https://cilogon.org/oauth/initiate'
    _OAUTH_VERSION = '1.0a'
    
    @gen.coroutine
    def get(self):
        self.redirect(url_concat('https://cilogon.org/delegate',
            {'oauth_token': resource_owner_key}))


class CILogonOAuthenticator(Authenticator):
    
    login_service = "CILogon"

    def login_url(self, base_url):
        return url_path_join(base_url, 'oauth_login')
    
    def get_handlers(self, app):
        return [
            (r'/oauth_login', CILogonHandler),
            (r'/oauth_callback', GitHubOAuthHandler),
        ]
    
    @gen.coroutine
    def authenticate(self, handler):
        r = requests.get(url_path_join(oauth_url, 'token'), auth=queryoauth,
                params=dict(
                    oauth_verifier=handler.get_argument('oauth_verifier'),
                    oauth_token=handler.get_argument('oauth_token'),
                )
        )
        r.raise_for_status()
        print(r.text)
        token = parse_qs(r.text)['oauth_token'][0]
        r = requests.get(url_path_join(oauth_url, 'getcert'), auth=queryoauth,
                params=dict(oauth_token=token))
        r.raise_for_status()
        print(r.text)
        line, cert_txt = r.text.split('\n', 1)
        
        cert = load_certificate(FILETYPE_PEM, cert_txt)
        username = None
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            print(ext.get_short_name(), ext.get_data())
            if ext.get_short_name().decode('ascii', 'replace') == 'subjectAltName':
                data = ext.get_data()
                username = data[4:].decode('utf8')
                break
        if not self.check_whitelist(username):
            self.log.warn("Rejecting user not in whitelist: %s", username)
            return
        return username
