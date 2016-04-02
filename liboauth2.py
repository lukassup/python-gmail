#!/usr/bin/python
#
# Copyright 2012 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# CHANGES
#
# - Adapted the original OAuth2 client library for Python 3.
#   Original: https://github.com/google/gmail-oauth2-tools/

"""\
Performs client tasks for testing IMAP OAuth2 authentication.

To use this script, you'll need to have registered with Google as an OAuth
application and obtained an OAuth client ID and client secret.
See https://developers.google.com/identity/protocols/OAuth2 for instructions on
registering and for documentation of the APIs invoked by this code.

This script has 3 modes of operation.

1. The first mode is used to generate and authorize an OAuth2 token, the
first step in logging in via OAuth2.

  oauth2 --user=xxx@gmail.com \\
    --client_id=1038[...].apps.googleusercontent.com \\
    --client_secret=VWFn8LIKAMC-MsjBMhJeOplZ \\
    --generate_oauth2_token

The script will converse with Google and generate an oauth request
token, then present you with a URL you should visit in your browser to
authorize the token. Once you get the verification code from the Google
website, enter it into the script to get your OAuth access token. The output
from this command will contain the access token, a refresh token, and some
metadata about the tokens. The access token can be used until it expires, and
the refresh token lasts indefinitely, so you should record these values for
reuse.

2. The script will generate new access tokens using a refresh token.

  oauth2 --user=xxx@gmail.com \\
    --client_id=1038[...].apps.googleusercontent.com \\
    --client_secret=VWFn8LIKAMC-MsjBMhJeOplZ \\
    --refresh_token=1/Yzm6MRy4q1xi7Dx2DuWXNgT6s37OrP_DW_IoyTum4YA

3. The script will generate an OAuth2 string that can be fed
directly to IMAP or SMTP. This is triggered with the --generate_oauth2_string
option.

  oauth2 --generate_oauth2_string --user=xxx@gmail.com \\
    --access_token=ya29.AGy[...]ezLg

The output of this mode will be a base64-encoded string. To use it, connect to a
IMAPFE and pass it as the second argument to the AUTHENTICATE command.

  a AUTHENTICATE XOAUTH2 a9sha9sfs[...]9dfja929dk==
"""

import base64
import json
from urllib.parse import quote, unquote, urlencode
from urllib.request import urlopen

# The URL root for accessing Google Accounts.
GOOGLE_ACCOUNTS_BASE_URL = 'https://accounts.google.com'

# Hardcoded dummy redirect URI for non-web apps.
REDIRECT_URI = 'urn:ietf:wg:oauth:2.0:oob'


def accounts_url(command):
    """Generates the Google Accounts URL.

    Args:
        command: The command to execute.

    Returns:
        A URL for the given command.
    """
    return '%s/%s' % (GOOGLE_ACCOUNTS_BASE_URL, command)


def url_escape(text):
    # See OAUTH 5.1 for a definition of which characters need to be escaped.
    return quote(text, safe='~-._')


def url_unescape(text):
    # See OAUTH 5.1 for a definition of which characters need to be escaped.
    return unquote(text)


def format_url_params(params):
    """Formats parameters into a URL query string.

    Args:
        params: A key-value map.

    Returns:
        A URL query string version of the given parameters.
    """
    param_fragments = list()
    for param in sorted(params.items(), key=lambda x: x[0]):
        param_fragments.append('%s=%s' % (param[0], url_escape(param[1])))
    return '&'.join(param_fragments)


def generate_permission_url(client_id, scope='https://mail.google.com/'):
    """Generates the URL for authorizing access.

    This uses the "OAuth2 for Installed Applications" flow described at
    https://developers.google.com/accounts/docs/OAuth2InstalledApp

    Args:
        client_id: Client ID obtained by registering your app.
        scope: scope for access token, e.g. 'https://mail.google.com'
    Returns:
        A URL that the user should visit in their browser.
    """
    params = dict()
    params['client_id'] = client_id
    params['redirect_uri'] = REDIRECT_URI
    params['scope'] = scope
    params['response_type'] = 'code'
    return '%s?%s' % (accounts_url('o/oauth2/auth'),
                    format_url_params(params))


def authorize_tokens(client_id, client_secret, authorization_code):
    """Obtains OAuth access token and refresh token.

    This uses the application portion of the "OAuth2 for Installed Applications"
    flow at https://developers.google.com/accounts/docs/OAuth2InstalledApp#handlingtheresponse

    Args:
        client_id: Client ID obtained by registering your app.
        client_secret: Client secret obtained by registering your app.
        authorization_code: code generated by Google Accounts after user grants
            permission.
    Returns:
        The decoded response from the Google Accounts server, as a dict. Expected
        fields include 'access_token', 'expires_in', and 'refresh_token'.
    """
    params = dict()
    params['client_id'] = client_id
    params['client_secret'] = client_secret
    params['code'] = authorization_code
    params['redirect_uri'] = REDIRECT_URI
    params['grant_type'] = 'authorization_code'
    request_url = accounts_url('o/oauth2/token')

    response = urlopen(request_url, urlencode(params).encode('ASCII')).read()
    return json.loads(response.decode('ASCII'))


def refresh_token(client_id, client_secret, refresh_token):
    """Obtains a new token given a refresh token.

    See https://developers.google.com/accounts/docs/OAuth2InstalledApp#refresh

    Args:
        client_id: Client ID obtained by registering your app.
        client_secret: Client secret obtained by registering your app.
        refresh_token: A previously-obtained refresh token.
    Returns:
        The decoded response from the Google Accounts server, as a dict. Expected
        fields include 'access_token', 'expires_in', and 'refresh_token'.
    """
    params = dict()
    params['client_id'] = client_id
    params['client_secret'] = client_secret
    params['refresh_token'] = refresh_token
    params['grant_type'] = 'refresh_token'
    request_url = accounts_url('o/oauth2/token')

    response = urlopen(request_url, urlencode(params)).read()
    return json.loads(response)


def generate_oauth2_string(username, access_token, base64_encode=True):
    """Generates an IMAP OAuth2 authentication string.

    See https://developers.google.com/google-apps/gmail/oauth2_overview

    Args:
        username: the username (email address) of the account to authenticate
        access_token: An OAuth2 access token.
        base64_encode: Whether to base64-encode the output.

    Returns:
        The SASL argument for the OAuth2 mechanism.
    """
    auth_string = 'user=%s\1auth=Bearer %s\1\1' % (username, access_token)
    if base64_encode:
        auth_string = base64.b64encode(auth_string)
    return auth_string

