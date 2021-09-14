import re
from flask import Blueprint, render_template

auth = Blueprint('auth', __name__)

@auth.route('/sign-up')
def sign_up():
  return render_template('signup.html')

@auth.route('/login')
def login():
  return render_template('login.html')