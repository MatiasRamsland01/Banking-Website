from os import error
import re
from flask import Blueprint, render_template, request, flash, redirect
from flask.helpers import url_for
from website.forms import RegisterForm, LoginForm, TransactionForm
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
    password1Hash = generate_password_hash(password1)
    
    return redirect(url_for('auth.home_login'))

  return render_template('signup.html', form=form)  

@auth.route('/homelogin', methods=['GET', 'POST'])
def home_login():
  return render_template('homelogin.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    logEmail = form.email.data
    logPassword = form.password.data
    return redirect(url_for('auth.home_login'))

  return render_template('login.html', form=form)

@auth.route('/transaction', methods=['GET', 'POST'])
def transaction():
  form = TransactionForm()
  if form.validate_on_submit():
    amount = form.amount.data
    to = form.amount.data
    return redirect(url_for('views.home'))

  
  return render_template('transaction.html', form=form)