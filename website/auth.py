from os import error
import re
import flask
import datetime
import flask_limiter
import flask_login
from flask import session
from flask import current_app
from flask import Blueprint, render_template, request, flash, redirect, abort, make_response
from flask.helpers import url_for
from flask_wtf.csrf import validate_csrf
from sqlalchemy import literal
from sqlalchemy.sql.expression import false
from website.db import User, init_db, db, Transaction
from flask_wtf.recaptcha.validators import Recaptcha
from website.forms import RegisterForm, LoginForm, TransactionForm, ATMForm
#from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import sha256
import pyotp
import os
import math
import re
from . import login_manager
from flask_login import login_required, logout_user, current_user, login_user
from flask import jsonify
from flask import request


from passlib.hash import argon2

auth = Blueprint('auth', __name__)

#When the user limit of 60 request within a minute this error handler occur
@auth.app_errorhandler(429)
def ratelimit_handler(e):
    logout_user()
    session['logged_in'] = False
    return make_response(
            jsonify(error="Ratelimit exceeded %s" % e.description+". Our BOT killer detected unusual manny request. Please slow down or turn of your BOT!")
            , 429
    )
    

# Timeout user when inactive in 5 min
@auth.before_request
def before_request():
    
    flask.session.permanent = True
    current_app.permanent_session_lifetime = datetime.timedelta(minutes=5)
    flask.session.modified = True
    flask.g.user = flask_login.current_user

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if current_user.is_authenticated:
        flash("You are already logged in")
        return redirect(url_for('auth.home_login'))
    form = RegisterForm()
    if form.validate_on_submit():
        init_db()
        if validate_password1(form.password1.data) and validate_username(form.username.data) and validate_email(form.username.data):

            # Correct input, now check database
            success = True
            user_by_username = User.query.filter_by(username=form.username.data).first()
            user_by_email = User.query.filter_by(email=form.email.data).first()
            if user_by_username:
                flash("Username taken!", category='error')
                success = False
            if user_by_email:
                flash("Email taken!", category='error')
                success = False
            if success:
                userName = form.username.data
                email = form.email.data
                password1 = form.password1.data
                hashedPassword = argon2.hash(password1)
                password2 = form.password2.data  # Prob redundant, unless we don't validate password in "form.validate_on_submit"
                secret = pyotp.random_base32()
                user = User(username=userName, email=email, password=hashedPassword, token = secret)
                db.session.add(user)
                db.session.commit()
                flash('Account Created', category='success')
                login_user(user)
                session['user'] = email
                session.permanent = True

                ##### Print statements to test values in database, comment away if not needed#########
                # print("Username: ", User.query.filter_by(username=form.username.data).first().username)
                # print("Email: ", User.query.filter_by(username=form.username.data).first().email)
                # print("Password: ", User.query.filter_by(username=form.username.data).first().password)
                ######################################################################################

                return redirect(url_for('auth.two_factor_view'))
            else:
                return redirect(url_for('views.home'))
    return render_template('signup.html', form=form)


@auth.route('/homelogin', methods=['GET'])
@login_required
def home_login():
    queried_from_user = User.query.filter_by(username=current_user.username).first()
    amount_in_database: int = queried_from_user.get_money()
    return render_template('homelogin.html', current_user=current_user.username, saldo=amount_in_database)


@auth.route('/atm', methods=['GET', 'POST'])
@login_required
def atm_transaction():
    form = ATMForm()
    if form.validate_on_submit():
        if validate_int(form.amount.data) and validate_username(form.username.data):
            take_out_money = True  # TODO PutInMoney logic through "ATM"

            
            amount = form.amount.data
            username = form.username.data
            success = True

            if amount < 1 or amount > 10_000:
                success = False
                flash('Amount needs to be between 1 and 10 000', category='error')

            user = User.query.filter_by(username=form.username.data).first()
            if not user:
                success = False
                flash(f"User with username {username} doesn't exist", category="error")

            if user and current_user.id != user.id:
                success = False
                flash("Can't transfer money from an account you don't own", category="error")

            otp = form.OTP.data
            if pyotp.TOTP(user.token).verify(otp) == False:
                success = False
                flash("Invalid OTP", category='error')
            
            if success:
                new_transaction = Transaction(to_user_id=username, in_money=amount)
                db.session.add(new_transaction)
                db.session.commit()
                return redirect(url_for('auth.home_login'))
        else:
            flash("Invalid request", category='error')
            return redirect(url_for('views.home'))

    return render_template('atm.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash("You are already logged in")
        return redirect(url_for('auth.home_login'))
    form = LoginForm()
    if form.validate_on_submit():
        if validate_password1(form.password.data) and validate_username(form.email.data):
            try:
                user = User.query.filter_by(email=form.email.data).first()
                otp = form.OTP.data
                if user is not None and argon2.verify(form.password.data, user.password) and pyotp.TOTP(user.token).verify(otp):
                    login_user(user)
                    session['logged_in']=True
                    return redirect(url_for('auth.home_login'))
                flash("Email, Password or OTP does not match!", category="error")
            except:
                flash("Something went wrong. Please try again", category="error")
        else:
            flash("Invalid request", category='error')
    return render_template('login.html', form=form)



# TODO Make user not be able to view this page again and not display secret in session variable (not safe)!
@auth.route('/two_factor_setup', methods=['GET'])
def two_factor_view():
    secret = current_user.token
    intizalize = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name='BankA250')
    return render_template('two-factor-setup.html', qr_link=intizalize)


@auth.route('/transaction', methods=['GET', 'POST'])
@login_required
def transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        if validate_username(form.from_user_name.data) and validate_username(form.to_user_name.data) and validate_string(form.message.data) and validate_int(form.amount.data):
            amount = form.amount.data
            from_user_name = form.from_user_name.data
            to_user_name = form.to_user_name.data
            message = form.message.data

            ATM_transaction = False  # TODO, if an ATM Transaction, then we dont need & shouldnt have both from & to
            success = True

            # Check if money amount is legal (between 1-200000)
            if amount < 1 or amount > 500_000:
                success = False
                flash("Money amount has to be a value between 1 and 500'000", category="error")
                # return render_template('transaction.html', form=form)

            # From ID and To ID exist
            queried_from_user = User.query.filter_by(username=from_user_name).first()
            queried_to_user = User.query.filter_by(username=to_user_name).first()
            if not queried_from_user:
                success = False
                flash(f"User with username {from_user_name} doesn't exist", category="error")
                # return render_template('transaction.html', form=form)
            if not queried_to_user:
                success = False
                flash(f"User with username {to_user_name} doesn't exist", category="error")
                # return render_template('transaction.html', form=form)

            # Trying to send money to himself
            if queried_from_user and current_user.username == queried_to_user.username:
                success = False
                flash("Can't send money to yourself", category="error")

            # TODO Finish has enough money
            amount_in_database: int = queried_from_user.get_money()
            flash("Money " + str(amount_in_database))
            if amount >= amount_in_database:
                success = False
                flash(f"Not enough money to send you have {amount_in_database} and you tried to send {amount}")

            # Is logged in on "from ID"
            if queried_from_user and queried_to_user and \
                    (current_user.id != queried_from_user.id or current_user.username != queried_from_user.username):
                success = False
                flash("Can't transfer money from an account you don't own", category="error")
            
            otp = form.OTP.data
            if pyotp.TOTP(queried_from_user.token).verify(otp) == False:
                success = False
                flash("Invalid OTP", category='error')

            if not success:
                flash("Unsuccessful transaction", category="error")
                return render_template('transaction.html', form=form)


            # TODO If everything is correct, register a transaction, and add it to the database
            #  Update (calculate) saldo if it's on the screen
            new_transaction = Transaction(out_money=amount, from_user_id=from_user_name, to_user_id=to_user_name,
                                        message=message)
            db.session.add(new_transaction)
            db.session.commit()

            return redirect(url_for('views.home'))
        else:
            flash("Invalid request", category='error')
            return redirect(url_for('views.home'))

    return render_template('transaction.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    session['logged_in'] = False
    session.clear()
    return redirect(url_for('auth.login'))


def validate_password1(password):
        bigLetter = 0
        smallLetter = 0
        number = 0
        illegal = 0
        sum = 0
        for letter in password:
            try: 
                if ord(letter) >= 48 and ord(letter) <= 57:
                    number += 1
                elif ord(letter) >= 97 and ord(letter) <= 122:
                    smallLetter += 1
                elif ord(letter) >= 65 and ord(letter) <= 90:
                    bigLetter += 1
                else:
                    illegal += 1
                sum += 1
                
            except:
                return False

        # Could tell the user what is missing and not just list everything. Might implement this later. It is just to add more if statements
        if bigLetter == 0 or smallLetter == 0 or number == 0 or illegal != 0 or sum < 7 or sum > 200:
            return False
        return True
            

def validate_username(username):
    if len(username) < 2 or len(username) > 50:
        return False
        
    for letter in username:
        try:
            ord(letter)
        except:
            return False
    return True
    
            
def validate_string(string):
    for letter in string:
        try:
            ord(letter)
        except:
            return False
    return True
    

def validate_int(integer):
    
    if isinstance(integer, int) == False: 
        return False
    return True
    


def validate_email(email):
    if len(email) < 3 or len(email) > 50:
        return False
        
    check = 0
    for letter in email:
        try:
            ord(letter)
            if ord(letter) == 64:
                check += 1

        except:
            return False
    return True
    
            
    
        
        


### Don't think this is necessary for our soloution with login users
"""
@login_manager.user_loader
def load_user(user_id):
    # Check if user is logged-in on every page load - didn't work with it yet
    if user_id is not None:
        return User.query.get(user_id)
    return None
"""
