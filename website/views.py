from flask import Blueprint, render_template


views = Blueprint('views', __name__)

#Our homepage
@views.route('/', methods=['GET', 'POST'])
def home():
    return render_template("home.html")
