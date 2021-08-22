import asyncio
import json
from authLib import exceptions
from authLib.auth import WyzeAuthLib

login_username = ""
login_password = ""


async def login():
    print("Starting")
    auth = WyzeAuthLib()
    credentials = None
    try:
        credentials = await auth.get_token_with_username_password(login_username, login_password)
    except exceptions.TwoFactorAuthentication:
        verification_code = input("Enter the verification code:")
        credentials = await auth.login_send_verification_code(verification_code)
    except ConnectionError:
        print("Received Error Code during login")
    finally:
        print(vars(credentials))


async def main():
    await asyncio.gather(login())

if __name__ == "__main__":
    asyncio.run(main())
