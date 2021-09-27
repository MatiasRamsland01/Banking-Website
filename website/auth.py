from os import error
import re
from flask import Blueprint, render_template, request, flash, redirect
from flask.helpers import url_for

from website import db
from website.db import User, init_db
from website.forms import RegisterForm, LoginForm, TransactionForm
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint('auth', __name__)


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    form = RegisterForm()
    if form.validate_on_submit():

        #TODO TEMP Testing
        init_db()

        #END
        # Correct input, now check database
        if not User.query.filter_by(username=form.nameFirst).first():#TODO TEMP username as firstName
            print(f"User {form.username} is already registered.")
        else:
            firstName = form.nameFirst.data
            lastName = form.nameLast.data
            email = form.email.data
            password1 = form.password1.data
            password2 = form.password2.data#Prob redundant, unless we don't validate password in "form.validate_on_submit"
            db.session.add(User(username=firstName, lastName=lastName, email=email, password=password1))
            db.session.commit()
            print(User.query.filter_by(username='test').first().password)
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
