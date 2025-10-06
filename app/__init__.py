from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__, instance_relative_config=False)
    
    # Uses simple config; to be changed for production
    app.config.from_object('config.Config')

    # Initializes extensions
    db.init_app(app)

    with app.app_context():
        from app import models # Models are supposed to be registered first
        db.create_all()

    # Imports blueprints/routes
    from app.routes import main
    app.register_blueprint(main)

    return app
