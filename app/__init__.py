import os
from flask import Flask
from dotenv import load_dotenv


def create_app() -> Flask:
    load_dotenv()

    base_dir = os.path.dirname(__file__)
    project_root = os.path.abspath(os.path.join(base_dir, ".."))

    app = Flask(
        __name__,
        template_folder=os.path.join(project_root, "templates"),
        static_folder=os.path.join(project_root, "static"),
    )
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB
    app.config["UPLOAD_FOLDER"] = os.path.join(project_root, "uploads")
    app.config["RULES_FOLDER"] = os.path.join(project_root, "rules")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

    # Ensure folders exist
    for folder in [app.config["UPLOAD_FOLDER"], app.config["RULES_FOLDER"]]:
        os.makedirs(os.path.abspath(folder), exist_ok=True)

    from .routes import bp

    app.register_blueprint(bp)
    return app


