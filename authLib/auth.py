
import time
import requests
import logging
import hashlib
import uuid
from authLib.token import Token
import authLib.constants as constants
import authLib.exceptions as exceptions


class WyzeAuthLib:
    def __init__(self):
        self.token = Token()
        self.token.set_phone_id(str(uuid.uuid4()))
        # store the verification_id, session_id and login_headers here as they are needed in both functions
        self.verification_id = ""
        self.session_id = ""
        self.login_headers = {
            'Phone-Id': self.token.get_phone_id(),
            'User-Agent': constants.APP_INFO,
            'X-API-Key': constants.API_KEY,
        }

    async def get_token_with_username_password(self, username: str, password: str, verification_code=None):
        for i in range(0, 3):
            password = hashlib.md5(password.encode('ascii')).hexdigest()

        # Store the username and hashed password in the token class
        self.token.set_user_name(username)
        self.token.set_user_password(password)

        payload = {'email': self.token.get_user_name(), 'password': self.token.get_user_password()}

        rsp = requests.post(
            constants.URL_LOGIN,
            headers=self.login_headers, json=payload).json()
        logging.debug(rsp)

        # Raise an exception if the result returns an error, such as too many failed attempts
        if 'errorcode' in rsp:
            raise exceptions.LoginError("Error: " + str(rsp['errorCode']) + " Description: " + rsp['description'])

        if rsp['mfa_options']:
            # Store the TOTP verification setting in the token and raise exception
            if "TotpVerificationCode" in rsp.get("mfa_options"):
                self.token.set_two_factor_type(Token.TWO_FACTOR_TOTP)
                # Store the verification_id from the response, it's needed for the 2fa payload.
                self.verification_id = rsp["mfa_details"]["totp_apps"][0]["app_id"]
                raise exceptions.TwoFactorAuthentication

            # 2fa using SMS, store sms as 2fa method in token, send the code then raise exception
            if "PrimaryPhone" in rsp.get("mfa_options"):
                self.token.set_two_factor_type(Token.TWO_FACTOR_SMS)
                params = {
                    'mfaPhoneType': 'Primary',
                    'sessionId': rsp['sms_session_id'],
                    'userId': rsp['user_id'],
                }
                payload = {}
                rsp = requests.post(
                    constants.URL_SEND_SMS,
                    headers=self.login_headers, params=params, json=payload).json()
                logging.debug(rsp)
                # Store the session_id from the response, it's needed for the 2fa payload.
                self.session_id = rsp['session_id']
                raise exceptions.TwoFactorAuthentication

        self.token.set_access_token(rsp['access_token'])
        self.token.set_refresh_token(rsp['refresh_token'])
        return self.token

    async def login_send_verification_code(self, verification_code):
        # TOTP Payload
        if self.token.get_two_factor_type() == Token.TWO_FACTOR_TOTP:
            payload = {
                "email": self.token.get_user_name(),
                "password": self.token.get_user_password(),
                "mfa_type": "TotpVerificationCode",
                "verification_id": self.verification_id,
                "verification_code": verification_code
            }
        # SMS Payload
        else:
            payload = {
                "email": self.token.get_user_name(),
                "password": self.token.get_user_password(),
                "mfa_type": "PrimaryPhone",
                "verification_id": self.session_id,
                "verification_code": verification_code
            }

        rsp = requests.post(
            constants.URL_LOGIN,
            headers=self.login_headers, json=payload).json()
        logging.debug(rsp)

        # Raise an exception if the result returns an error, such as too many failed attempts
        if 'errorcode' in rsp:
            raise exceptions.LoginError("Error: " + str(rsp['errorCode']) + " Description: " + rsp['description'])

        self.token.set_access_token(rsp['access_token'])
        self.token.set_refresh_token(rsp['refresh_token'])
        return self.token
