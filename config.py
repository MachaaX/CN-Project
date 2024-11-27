# config.py
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'type_your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI') or 'mysql+pymysql://root:admin@localhost/healthcare_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
