from flask import Blueprint, render_template#from website import db
#from website.db import User, init_db
from flask import session


views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
def home():
   
    return render_template("home.html")
