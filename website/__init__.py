from flask import Flask, flash

def create_app():
  app = Flask(__name__)
  app.secret_key = 'rbgweqrty894t37t7eiuwbgnp ubiq fviuq'

  from .views import views
  from .auth import auth

  app.register_blueprint(views, url_prefix='/')
  app.register_blueprint(auth, url_prefix='/')

  return app
