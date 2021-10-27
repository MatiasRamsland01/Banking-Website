import os
import re
import click
from flask import Flask, flash
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from flask_recaptcha import ReCaptcha
from flask_qrcode import QRcode
from flask_login import LoginManager
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from sqlalchemy import create_engine
from werkzeug.exceptions import _RetryAfter
import psycopg2



login_manager = LoginManager()



app = Flask(__name__)




uri = os.getenv("DATABASE_URL")  # or other relevant config var
if uri.startswith("postgres://"): # from SQLAlchemy 1.14, the uri must start with postgresql, not postgres, which heroku provides
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
engine = create_engine('postgres://buqhzjmcawhhfr:8f73741c058148e9b4a76c518a97ba058e185b906befd7c04da8be64550352a6@ec2-63-33-14-215.eu-west-1.compute.amazonaws.com:5432/dftbvhkp89or2n')

DATABASE_URL = os.environ['DATABASE_URL'] #From heroku postgresql documentation
conn = psycopg2.connect(DATABASE_URL, sslmode='require') #From heroku postgresql documentation
db = SQLAlchemy(app)


csp = {
'default-src': [
    '\'self\'',
    '\'unsafe-inline\'',
    'stackpath.bootstrapcdn.com',
    'code.jquery.com',
    'cdn.jsdelivr.net',
    'https://www.google.com/recaptcha/',
    'https://www.gstatic.com/recaptcha/',
    ],
'img-src': ['\'self\'', '*', 'data:']    
}

Talisman(app, content_security_policy=csp)

csrf = CSRFProtect()
csrf.init_app(app)

"""
db_url = os.environ.get("DATABASE_URL")
if db_url is None:
    # default to a sqlite database in the instance folder
    db_path = os.path.join(app.instance_path, "flaskr.sqlite")
    db_url = f"sqlite:///{db_path}"
    # ensure the instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)
"""
#app.config['SQLALCHEMY_DATABASE_URI'] = db_url

app.config['SECRET_KEY'] = 'bd5049afa301c7c5d709f821'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeJKpYcAAAAAK9NxeH7cNAPl9BWMQk16hkMdpFy'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeJKpYcAAAAAIK7he7W0f490MZ-t_V_8cDYFDCK'
app.config['RECAPTCHA_ENABLED'] = False
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=2)

ReCaptcha(app)
QRcode(app)
#db.init_app(app)
#app.cli.add_command(init_db_command)

from .views import views
from .auth import auth

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = "You need to log in to access this page!"
login_manager.login_message_category = 'error'
login_manager.init_app(app)

limiter = Limiter(
app,
key_func=get_remote_address,
application_limits=["60 per minute",]
)

from .db import User

@login_manager.user_loader
def load_user(id):
    try: 
        return User.query.get(int(id))
    except:
        return None


app.register_blueprint(views, url_prefix='/')
app.register_blueprint(auth, url_prefix='/')






#@click.command("init-db")
#@with_appcontext
#def init_db_command():
#    """Clear existing data and create new tables."""
#    init_db()
#    click.echo("Initialized the database.")
