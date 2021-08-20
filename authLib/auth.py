import re
import time
import requests
import logging
import hashlib
import uuid
from authLib.token import Token
import authLib.constants as constants


class WyzeAuthLib:
    def __init__(self):
        self.token = Token()

    def get_token_with_username_password(self, username: str, password: str):
        self.token.set_user_name(username)

        # Don't re-hash the password if it's already hashed
        if not re.findall(r"([a-fA-F\d]{32})", password):
            for i in range(0, 3):
                password = hashlib.md5(password.encode('ascii')).hexdigest()

        # Store the hashed password in the token class
        self.token.set_user_password(password)
        self.token.set_phone_id(str(uuid.uuid4()))

        headers = {
            'Phone-Id': self.token.get_phone_id(),
            'User-Agent': constants.APP_INFO,
            'X-API-Key': constants.API_KEY,
        }

        payload = {'email': self.token.get_user_name(), 'password': self.token.get_user_password()}
        rsp = requests.post(
            constants.URL_LOGIN,
            headers=headers, json=payload).json()
        logging.debug(rsp)

        # Raise a connection error if the result returns an error, such as too many failed attempts
        if 'errorcode' in rsp:
            print("Error: " + str(rsp['errorCode']) +
                  " Description: " + rsp['description'])
            raise ConnectionError

        if not rsp['access_token']:
            self.token.set_two_factor_enabled(True)
            if "TotpVerificationCode" in rsp.get("mfa_options"):
                # Yield to obtain 2FA Token from calling function
                verification_code = yield self.token

                payload = {
                    "email": self.token.get_user_name(),
                    "password": self.token.get_user_password(),
                    "mfa_type": "TotpVerificationCode",
                    "verification_id": rsp["mfa_details"]["totp_apps"][0]["app_id"],
                    "verification_code": verification_code
                }

            else:
                params = {
                    'mfaPhoneType': 'Primary',
                    'sessionId': rsp['sms_session_id'],
                    'userId': rsp['user_id'],
                }

                payload = {}
                rsp = requests.post(
                    constants.URL_SEND_SMS,
                    headers=headers, params=params, json=payload).json()
                logging.debug(rsp)
                session_id = rsp['session_id']

                # Yield to obtain 2FA Token from calling function
                verification_code = yield self.token

                payload = {
                    "email": self.token.get_user_name(),
                    "password": self.token.get_user_password(),
                    "mfa_type": "PrimaryPhone",
                    "verification_id": session_id,
                    "verification_code": verification_code}

            rsp = requests.post(
                constants.URL_LOGIN,
                headers=headers, json=payload).json()
            logging.debug(rsp)

        self.token.set_access_token(rsp['access_token'])
        self.token.set_refresh_token(rsp['refresh_token'])
        yield self.token
