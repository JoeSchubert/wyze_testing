import time


class Token:
    refresh_time_threshold = 3600

    def __init__(self, phone_id=None, user_name=None, user_password=None, access_token=None, refresh_token=None,
                 refresh_time=None, two_factor_enabled=False):
        self.phone_id: str = phone_id
        self.user_name: str = user_name
        self.user_password: str = user_password
        self.access_token: str = access_token
        self.refresh_token: str = refresh_token
        self.refresh_time: float = refresh_time
        self.two_factor_enabled: bool = two_factor_enabled

    def set_phone_id(self, phone_id: str):
        self.phone_id = phone_id

    def get_phone_id(self):
        return self.phone_id

    def set_user_name(self, user_name: str):
        self.user_name = user_name

    def get_user_name(self):
        return self.user_name

    def set_user_password(self, user_password: str):
        self.user_password = user_password

    def get_user_password(self):
        return self.user_password

    def set_access_token(self, access_token: str):
        self.access_token = access_token
        self.refresh_time = time.time() + self.refresh_time_threshold

    def get_access_token(self):
        return self.access_token

    def set_refresh_token(self, refresh_token: str):
        self.refresh_token = refresh_token

    def get_refresh_token(self):
        return self.refresh_token

    # Refresh time not settable, it is set when storing an access token.

    def get_refresh_time(self):
        return self.refresh_time

    def set_two_factor_enabled(self, enabled: bool):
        self.two_factor_enabled = enabled

    def get_two_factor_enabled(self):
        return self.two_factor_enabled
