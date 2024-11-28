# models.py
from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    __tablename__ = 'users'  # Ensure table name matches your SQL schema
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role_name = db.Column(db.Enum('patient', 'nurse', 'doctor'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    patient = db.relationship('Patient', backref='user', uselist=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Patient(db.Model):
    __tablename__ = 'patients'
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True)
    address = db.Column(db.LargeBinary)  # Encrypted address
    age = db.Column(db.Integer)
    height = db.Column(db.Numeric(5, 2))
    weight = db.Column(db.Numeric(5, 2))
    sex = db.Column(db.String(10))

    health_data = db.relationship('HealthData', backref='patient', lazy=True)
    comments = db.relationship('Comment', backref='patient', lazy=True)
    prescriptions = db.relationship('Prescription', backref='patient', lazy=True)

    def __repr__(self):
        return f'<Patient {self.user.username}>'

class HealthData(db.Model):
    __tablename__ = 'health_data'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.user_id', ondelete='CASCADE'), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=True)  # Store encrypted file data as binary
    filename = db.Column(db.String(255))
    symptoms = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<HealthData {self.id} for Patient {self.patient_id}>'


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.user_id', ondelete='CASCADE'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.Enum('doctor', 'nurse'), nullable=False)

    author = db.relationship('User', backref='comments')

    def __repr__(self):
        return f'<Comment {self.id} by {self.author.username}>'

class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.user_id', ondelete='CASCADE'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    prescription = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    doctor = db.relationship('User', backref='prescriptions', foreign_keys=[doctor_id])

    def __repr__(self):
        return f'<Prescription {self.id} for Patient {self.patient_id}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
