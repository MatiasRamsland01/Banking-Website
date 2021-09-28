from os import error
import re
from flask import current_app
from flask import Blueprint, render_template, request, flash, redirect
from flask.helpers import url_for
from sqlalchemy import literal
from website import db
from website.db import User, init_db
from flask_wtf.recaptcha.validators import Recaptcha
from website.forms import RegisterForm, LoginForm, TransactionForm
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    form = RegisterForm()
    if form.validate_on_submit():

        # TODO TEMP Testing
        #init_db()

        # END
        # Correct input, now check database
        q = db.session.query(User).filter(User.username == form.nameFirst.data)

        if db.session.query(literal(True)).filter(q.exists()).scalar():  # TODO TEMP username as firstName
            flash("Account already created!", category='error')
        else:
            firstName = form.nameFirst.data
            lastName = form.nameLast.data
            email = form.email.data
            password1 = form.password1.data
            password2 = form.password2.data  # Prob redundant, unless we don't validate password in "form.validate_on_submit"
            db.session.add(User(username=firstName, email=email, password=password1))
            db.session.commit()
            flash('Account Created', category='success')
            # print(User.query.filter_by(username=form.nameFirst.data).first().password)
            return redirect(url_for('auth.two_factor_setup'))

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


@auth.route('/two_factor_setup')
def two_factor_setup():
    return render_template('two-factor-setup.html')


@auth.route('/transaction', methods=['GET', 'POST'])
def transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        amount = form.amount.data
        to = form.amount.data
        return redirect(url_for('views.home'))

    return render_template('transaction.html', form=form)
