from os import error
import re
from flask import Blueprint, render_template, request, flash, redirect
from flask.helpers import url_for
from website.forms import RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
  form = RegisterForm()
  if form.validate_on_submit():
    firstName = form.nameFirst.data
    lastName = form.nameLast.data
    email = form.email.data
    password1 = form.password1.data
    password2 = form.password2.data
    return redirect(url_for('views.home'))

  return render_template('signup.html', form=form)  



@auth.route('/login', methods=['GET', 'POST'])
def login():
  return render_template('login.html')
