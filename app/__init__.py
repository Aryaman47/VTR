import os

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__, instance_relative_config=False)
    
    config_name = os.environ.get("APP_CONFIG", "config.DevelopmentConfig")
    app.config.from_object(config_name)

    if config_name == "config.ProductionConfig":
        from config import ProductionConfig
        ProductionConfig.validate()

    # Initializes extensions
    db.init_app(app)

    with app.app_context():
        from app import models # Models are supposed to be registered first
        if app.config.get("TESTING") or app.config.get("DEBUG"):
            db.create_all()

    # Imports blueprints/routes
    from app.routes import main
    app.register_blueprint(main)

    @app.get("/health")
    def health_check():
        return jsonify({"status": "ok"})

    return app
