# app.py
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import logging
from logging.handlers import RotatingFileHandler
import os

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to 'login' when @login_required fails
login_manager.login_message_category = 'info'
bcrypt = Bcrypt(app)

if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/healthcare_app.log', maxBytes=10240, backupCount=10)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    file_handler.setFormatter(formatter)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Healthcare App Startup')

from routes import *  # Import routes at the end to avoid circular imports

if __name__ == '__main__':
    # For local development with HTTPS (optional)
    # app.run(ssl_context=('cert.pem', 'key.pem'))
    app.run(host='0.0.0.0', port=5000, debug=True)
    # app.run(debug=True)