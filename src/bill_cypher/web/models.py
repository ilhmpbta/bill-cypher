from flask_login import UserMixin


class User(UserMixin):
    def __init__(self, id: int, username: str, password_hash: str) -> None:
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def get_id(self) -> str:
        return str(self.id)
