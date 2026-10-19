import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from ..db import close_db, get_user_by_id, init_db
from .models import User

load_dotenv()

csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = "auth.login"  # type: ignore[assignment]  # flask-login stub bug
login_manager.session_protection = "strong"  # type: ignore[assignment]  # same stub bug


@login_manager.user_loader
def load_user(user_id: str):
    row = get_user_by_id(int(user_id))
    if row is None:
        return None
    return User(
        id=row["id"],
        username=row["username"],
        password_hash=row["password_hash"],
    )


def create_app(test_config=None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)

    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        raise KeyError("SECRET_KEY environment variable is missing.")

    base_dir = Path(__file__).resolve().parent.parent.parent
    data_dir = base_dir / "data"
    data_dir.mkdir(exist_ok=True)

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        DATABASE=data_dir / "bill_cypher.db",
        BLOB_DIR=data_dir / "blobs",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        MAX_CONTENT_LENGTH=512 * 1024 * 1024,
    )

    if test_config is not None:
        app.config.update(test_config)

    # Ensure blob dir exists
    Path(app.config["BLOB_DIR"]).mkdir(exist_ok=True, parents=True)

    csrf.init_app(app)
    login_manager.init_app(app)

    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    from .auth import bp as auth_bp

    app.register_blueprint(auth_bp)

    return app
