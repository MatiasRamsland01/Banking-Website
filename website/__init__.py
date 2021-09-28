from flask import Flask, flash
from flask_recaptcha import ReCaptcha
def create_app():
  app = Flask(__name__)
  app.config['SECRET_KEY'] = 'bd5049afa301c7c5d709f821'
  app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeJKpYcAAAAAK9NxeH7cNAPl9BWMQk16hkMdpFy'
  app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeJKpYcAAAAAIK7he7W0f490MZ-t_V_8cDYFDCK'
  ReCaptcha(app)
  from .views import views
  from .auth import auth

  app.register_blueprint(views, url_prefix='/')
  app.register_blueprint(auth, url_prefix='/')

  return app

