from authLib.auth import WyzeAuthLib

login_username = ""
login_password = ""

login = WyzeAuthLib().get_token_with_username_password(login_username, login_password)

try:
    credentials = next(login)

    if credentials.get_two_factor_enabled():
        print("2fa on account")
        verification_code = input("Enter the verification code:")
        credentials = login.send(verification_code)
        print(vars(credentials))
    else:
        print("No 2fa on account")
        print(vars(credentials))

    if credentials.get_access_token():
        login.close()
except ConnectionError:
    login.close()
