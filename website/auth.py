from os import error
import re
from flask import session
from flask import current_app
from flask import Blueprint, render_template, request, flash, redirect
from flask.helpers import url_for
from sqlalchemy import literal
from website import db
from website.db import User, init_db
from flask_wtf.recaptcha.validators import Recaptcha
from website.forms import RegisterForm, LoginForm, TransactionForm
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import os
from . import login_manager
from flask_login import login_required, logout_user, current_user, login_user

auth = Blueprint('auth', __name__)


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    form = RegisterForm()
    if form.validate_on_submit():

        # TODO TEMP Testing
        init_db()

        # END
        # Correct input, now check database
        q = db.session.query(User).filter(User.username == form.nameFirst.data)

        if db.session.query(literal(True)).filter(q.exists()).scalar():  # TODO TEMP username as firstName
            flash("Account already created!", category='error')
        else:
            firstName = form.nameFirst.data
            lastName = form.nameLast.data # Value unused
            email = form.email.data
            password1 = form.password1.data
            hashedPassword = generate_password_hash(password1, method="sha256")
            password2 = form.password2.data  # Prob redundant, unless we don't validate password in "form.validate_on_submit"
            user = User(username=firstName, email=email, password=hashedPassword)
            db.session.add(user)
            db.session.commit()
            flash('Account Created', category='success')
            session['user'] = email
            session.permanent = True
            login_user(user)
            session['logged_in']=True

            ##### Print statements to test values in database, comment away if not needed#########
            print("Username: ", User.query.filter_by(username=form.nameFirst.data).first().username)
            print("Email: ", User.query.filter_by(username=form.nameFirst.data).first().email)
            print("Password: ", User.query.filter_by(username=form.nameFirst.data).first().password)
            ######################################################################################

            return redirect(url_for('auth.two_factor_view', email=email))
    return render_template('signup.html', form=form)


@auth.route('/homelogin', methods=['GET', 'POST'])
@login_required
def home_login():
    return render_template('homelogin.html', current_user=current_user.username)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and check_password_hash(user.password, form.password.data):
            login_user(user)
            session['logged_in']=True
            return redirect(url_for('auth.home_login'))
        flash("Email or password does not match!", category="error")
    return render_template('login.html', form=form)


@auth.route('/two_factor_setup', methods=['GET'])
def two_factor_view():
    try:
        email = request.args['email']
    except KeyError:
        flash("You don't have access to this page", category='error')
        return redirect(url_for('auth.sign_up'))
    secret = pyotp.random_base32()
    intizalize = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name='BankDat250')
    session['secret'] = secret
    return render_template('two-factor-setup.html', qr_link = intizalize )

@auth.route('/transaction', methods=['GET', 'POST'])
@login_required
def transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        amount = form.amount.data
        to = form.amount.data
        return redirect(url_for('views.home'))

    return render_template('transaction.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session['logged_in']=False
    return redirect(url_for('auth.login'))

### Don't think this is necessary for our soloution with login users
"""
@login_manager.user_loader
def load_user(user_id):
    # Check if user is logged-in on every page load - didn't work with it yet
    if user_id is not None:
        return User.query.get(user_id)
    return None
"""
