from os import error
import re
from flask import Blueprint, render_template, request, flash

auth = Blueprint('auth', __name__)

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
  if request.method == 'POST':
    name = request.form.get('name')
    email = request.form.get('email')
    password1 = request.form.get('password1')
    password2 = request.form.get('password2')
    if len(name) < 2:
      flash('Name needs to be greater than 1 character', category='error')

    #Pseudo code: if input not valid --> print error message --> else: add user to database

  return render_template('signup.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    logEmail = request.form.get('email')
    logPassword = request.form.get('password1')

  return render_template('login.html')