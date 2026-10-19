from .envelope import decryptbytes, encryptbytes

__all__ = ["decryptbytes", "encryptbytes", "main"]
__version__ = "0.1.0"


def main() -> None:
    from .web import create_app

    app = create_app()
    app.run(debug=True)
