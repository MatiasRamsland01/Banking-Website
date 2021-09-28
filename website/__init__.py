import os
import click
from flask import Flask, flash
from flask.cli import with_appcontext
from flask_sqlalchemy import SQLAlchemy
from flask_recaptcha import ReCaptcha

db = SQLAlchemy()

def create_app():
  app = Flask(__name__)

  db_url = os.environ.get("DATABASE_URL")

  if db_url is None:
    # default to a sqlite database in the instance folder
    db_path = os.path.join(app.instance_path, "flaskr.sqlite")
    db_url = f"sqlite:///{db_path}"
    # ensure the instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)

  app.config['SECRET_KEY'] = 'bd5049afa301c7c5d709f821'
  app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeJKpYcAAAAAK9NxeH7cNAPl9BWMQk16hkMdpFy'
  app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeJKpYcAAAAAIK7he7W0f490MZ-t_V_8cDYFDCK'
  app.config['SQLALCHEMY_DATABASE_URI']=db_url
  app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

  ReCaptcha(app)
  
  db.init_app(app)
  app.cli.add_command(init_db_command)

  from .views import views
  from .auth import auth

  app.register_blueprint(views, url_prefix='/')
  app.register_blueprint(auth, url_prefix='/')

  return app

def init_db():
  db.drop_all()
  db.create_all()


@click.command("init-db")
@with_appcontext
def init_db_command():
  """Clear existing data and create new tables."""
  init_db()
  click.echo("Initialized the database.")