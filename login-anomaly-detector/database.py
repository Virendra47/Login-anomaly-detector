from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120))
    role = db.Column(db.String(50), default='user')
    failed_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)
    lockout_until = db.Column(db.DateTime, nullable=True)
    last_successful_login = db.Column(db.DateTime, nullable=True)
    baseline_hours = db.Column(db.String(100), default="9-17")  # e.g., "9-17" or "0-23"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    hour = db.Column(db.Integer, nullable=False)
    success = db.Column(db.Boolean, default=False)
    
class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    alert_type = db.Column(db.String(50), nullable=False)  # multiple_failures, unusual_timing, account_locked
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    message = db.Column(db.String(500), nullable=False)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)

def init_db(app):
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")