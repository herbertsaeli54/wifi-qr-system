from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    qr_token = db.Column(db.String(200))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True)
    registered_at = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(128))  # New field

    # Method to set hashed password
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to verify password
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Relationship (optional if you use backref from Session)
    sessions = db.relationship('Session', backref='user', lazy=True)



