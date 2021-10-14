from flask import Blueprint, render_template
from website.db import db
    

views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST'])
def home():
    db.drop_all()
    db.create_all()
    return render_template("home.html")
