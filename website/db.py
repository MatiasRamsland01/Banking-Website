from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)  # main.get_app()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=False, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        # Create hashed password
        self.password = generate_password_hash(
            password,
            method='sha256'
        )

    def check_password(self, password):
        # return check_password_hash(self.password, password)
        if self.password == password:
            return True

    def get_money(self):
        return 0 #db. # TODO


class Transaction(db.Model):
    transaction_id = db.Column(db.Integer, primary_key=True)
    # Out Id & Money can be null because we might put in (or take out) money through an ATM
    from_user_id = db.Column(db.Integer, nullable=True)  # TODO ForeignKey?
    out_money = db.Column(db.String(40), nullable=True)
    to_user_id = db.Column(db.Integer)  # TODO ForeignKey?
    in_money = db.Column(db.String(40))
    message = db.Column(db.String(120))
    # TimeStamp?

    def __eq__(self, other):
        return self.transaction_id == other.transaction_id


def init_db():
    db.create_all()
