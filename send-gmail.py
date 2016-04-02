#!/usr/bin/env python
# -*- coding: utf-8 -*-

from smtplib import SMTP
from base64 import b64encode
from email.mime.text import MIMEText
from getpass import getpass
import liboauth2

GMAIL_SMTP = "smtp.gmail.com"
SCOPE = "https://mail.google.com/"

# Message body
msg = MIMEText("""\
Hello from Python 3
""")

msg["Subject"] = "Hello world!"
msg["From"] = "you@gmail.com" # Your Google email
msg["To"] = "your.friend@gmail.com"

# OAuth2 stuff
# 0. Read the docstring in 'liboauth2.py'
# 1. Request and authorize an OAuth2 token

client_id = getpass("Enter client ID: ")
client_secret = getpass("Enter client secret: ")
print("To authorize token, visit:")
print(liboauth2.generate_permission_url(client_id, SCOPE))

auth_code = getpass("Enter authorization code: ")
response = liboauth2.authorize_tokens(client_id, client_secret, auth_code)
print("Refresh token:", response["refresh_token"])
print("Access token:", response["access_token"])
print("Access token expires in {0} seconds".format(response["expires_in"]))

# 2. Use the access token to generate an OAuth2 string

# A single token can be used multiple times for 1 hour once authorized
#access_token = getpass("Enter access token: ")
access_token = reponse["access_token"]

auth_string = liboauth2.generate_oauth2_string(
        msg["From"],
        access_token,
        base64_encode=False) 

with SMTP(GMAIL_SMTP, 587) as smtp_conn:
    smtp_conn.set_debuglevel(True)
    smtp_conn.ehlo_or_helo_if_needed()
    smtp_conn.starttls()
    smtp_conn.ehlo_or_helo_if_needed()
    smtp_conn.docmd('AUTH', 'XOAUTH2 ' +
            b64encode(auth_string.encode('ASCII')).decode("UTF-8"))
    smtp_conn.sendmail(msg['From'], [msg['To']], msg.as_string())

print("Email sent!")

