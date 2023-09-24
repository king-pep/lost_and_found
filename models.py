from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), unique=False, nullable=False)
    last_name = db.Column(db.String(80), unique=False, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True, info={'unique_constraint': 'uq_email'})
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, nullable=True)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    items = db.relationship('Item', backref='reporter', lazy=True)
    profile_visibility = db.Column(db.String(50), default='public', nullable=False)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver',
                                        lazy='dynamic')
    claims = db.relationship('Claim', back_populates='user')

    PROFILE_VISIBILITY_CHOICES = ['public', 'private']

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, index=True)  # Added index
    description = db.Column(db.String(300), nullable=False, index=True)  # Added index
    category = db.Column(db.String(100), nullable=False, index=True)  # Added index
    location = db.Column(db.String(200), nullable=False, index=True)  # Added index
    time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    type = db.Column(db.String(10), nullable=False, index=True)  # This will store values "lost" or "found"
    image_file = db.Column(db.String(20), nullable=True, default='default.jpg')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    claims = db.relationship('Claim', back_populates='item')


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=True)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, user_id, message, item_id=None):
        self.user_id = user_id
        self.message = message
        self.item_id = item_id


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # messages = db.relationship('Message', backref='conversation', lazy=True)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    # conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)


class Claim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    claim_status = db.Column(db.String(50))
    submitted_proof = db.Column(db.String(200))

    # Relationships
    item = db.relationship('Item', back_populates='claims')
    user = db.relationship('User', back_populates='claims')
