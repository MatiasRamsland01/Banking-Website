from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)  # main.get_app()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column( db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=False, nullable=False)
    # TODO Might be temporary, we probably dont want to store money with user info.
    money = db.Column(db.String(40), unique=False, nullable=True)  # db.Numeric(16, True)

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


def init_db():
    db.drop_all()
    db.create_all()

    # admin = User(username='admin', email='admin@example.com', password='Test123#')
    # guest = User(username='guest', email='guest@example.com', password='Test123#')
    # admin.money = "32.123456789101112"

    # db.session.add(admin)
    # db.session.add(guest)
    # db.session.commit()

# TEST
# db.drop_all()
# db.create_all()

# admin = User(username='admin', email='admin@example.com', password='Test123#')
# guest = User(username='guest', email='guest@example.com', password='Test123#')
# admin.money = "32.123456789101112"

# db.session.add(admin)
# db.session.add(guest)
# db.session.commit()

# User.query.all()
# queried_admin = User.query.filter_by(email ='admin@example.com').first()
# queried_guest = User.query.filter_by(username='guest').first()
# print(str(queried_admin)+" "+str(queried_admin.id)+" "+str(queried_guest.id)+"_"+str(queried_admin.money))
