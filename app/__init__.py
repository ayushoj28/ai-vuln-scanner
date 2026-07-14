"""
__init__.py — Flask application factory.
Auto-trains model on first startup if not already trained.
"""

import os
from flask import Flask


def create_app():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    static_dir = os.path.join(base_dir, "static")

    flask_app = Flask(__name__, static_folder=static_dir, static_url_path="")

    # Load / auto-train the ML model
    from app.model import VulnerabilityModel
    model = VulnerabilityModel()

    if not model.is_loaded():
        print("[INIT] Model not found. Running auto-training...")
        from app.train import train_model
        train_model()
        model._load()

    flask_app.vuln_model = model

    # Register routes
    from app.routes import bp
    flask_app.register_blueprint(bp)

    return flask_app
