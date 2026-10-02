from flask import Flask
from capx.config import config
from capx.api.web_routes import web_bp
import os

def create_app() -> Flask:
    """Initializes the CAPX Flask application."""
    
    # Point Flask to our root templates and static folders
    template_dir = os.path.abspath(os.path.join(config.BASE_DIR, 'templates'))
    static_dir = os.path.abspath(os.path.join(config.BASE_DIR, 'static'))
    
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.register_blueprint(web_bp)
    
    return app