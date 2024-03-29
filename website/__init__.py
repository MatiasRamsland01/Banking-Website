import os
from flask import Flask
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



login_manager = LoginManager()


app = Flask(__name__)

#For heroku
##############################


uri = os.getenv("DATABASE_URL")  # or other relevant config var
if uri.startswith("postgres://"): # from SQLAlchemy 1.14, the uri must start with postgresql, not postgres, which heroku provides
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri

##############################


#Content security policy, tells what flask-talisman should allow
csp = {
'default-src': [
    '\'self\'',
    '\'unsafe-inline\'',
    'stackpath.bootstrapcdn.com',
    'code.jquery.com',
    'cdnjs.cloudflare.com/',
    'maxcdn.bootstrapcdn.com',
    'https://www.google.com/recaptcha/',
    'https://www.gstatic.com/recaptcha/',
    ],
'img-src': ['\'self\'', '*', 'data:']    
}

Talisman(app, content_security_policy=csp)

#Sets up the CSRF
csrf = CSRFProtect()
csrf.init_app(app)

#Used locally
##############################
"""
db_url = os.environ.get("DATABASE_URL")
if db_url is None:
    # default to a sqlite database in the instance folder
    db_path = os.path.join(app.instance_path, "flaskr.sqlite")
    db_url = f"sqlite:///{db_path}"
    # ensure the instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
"""
##############################



app.config['SECRET_KEY'] = 'bd5049afa301c7c5d709f821'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeJKpYcAAAAAK9NxeH7cNAPl9BWMQk16hkMdpFy'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeJKpYcAAAAAIK7he7W0f490MZ-t_V_8cDYFDCK'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=2)
db = SQLAlchemy(app)

ReCaptcha(app)
QRcode(app)
db.init_app(app)



from website.views import views
from website.auth import auth

#Sets up login mananger and sets pages and message when violated
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = "You need to log in to access this page!"
login_manager.login_message_category = 'error'
login_manager.init_app(app)

#Setup for request limiter
limiter = Limiter(
app,
key_func=get_remote_address,
application_limits=["60 per minute",]
)

from website.db import User

@login_manager.user_loader
def load_user(id):
    try: 
        return User.query.get(int(id))
    except:
        return None


app.register_blueprint(views, url_prefix='/')
app.register_blueprint(auth, url_prefix='/')




