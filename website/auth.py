from website import db
import datetime
import re
from hashlib import sha256
from flask import session
import flask
import flask_login
import pyotp
from blinker import Namespace
from flask import Blueprint, render_template, flash, redirect, make_response
from flask import current_app
from flask import Blueprint, render_template, flash, redirect, make_response
from flask.helpers import url_for
from website.db import User, Transaction, EncryptMsg, DecryptMsg, Logs, init_db
from website.forms import RegisterForm, LoginForm, TransactionForm, ATMForm
from hashlib import sha256
import pyotp
import re
from flask_login import login_required, logout_user, current_user, login_user
from flask import jsonify
from passlib.hash import argon2
from website.db import User, Transaction, EncryptMsg, Logs
from website.forms import RegisterForm, LoginForm, TransactionForm, ATMForm

my_signals = Namespace()

auth = Blueprint('auth', __name__)


def add_user():
    # add user code here
    user_added = my_signals.signal('user-added')


# When the user limit of 60 request within a minute this error handler occur
@auth.app_errorhandler(429)
def ratelimit_handler(e):
    try:
        message = "Request Limit: User: " + current_user.username + ". Time: " + str(datetime.datetime.now())
    except:
        message = "Request Limit: User: None . Time: " + str(datetime.datetime.now())
    db.session.add(Logs(log=message))
    db.session.commit()
    logout_user()
    session['logged_in'] = False
    return make_response(
        jsonify(
            error="Ratelimit exceeded %s" % e.description + ". Our BOT killer detected unusual manny request. Please slow down or turn of your BOT!")
        , 429
    )

"""
@auth.errorhandler(Exception)
def basic_error(e):
    flash("Something went wrong", category='error')
    return redirect(url_for('auth.home_login'))
"""

# Timeout user when inactive in 5 min
@auth.before_request
def before_request():
    flask.session.permanent = True
    current_app.permanent_session_lifetime = datetime.timedelta(minutes=5)
    flask.session.modified = True
    flask.g.user = flask_login.current_user


def FinnHash(string):
    encoded = string.encode()
    theHash = sha256(encoded).hexdigest()
    return theHash


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if current_user.is_authenticated:
        flash("You are already logged in")
        return redirect(url_for('auth.home_login'))
    form = RegisterForm()
    if form.validate_on_submit():
        init_db()

        if validate_password(form.password1.data) and validate_username(form.username.data) \
                and validate_email(form.email.data) and validate_password(form.password2.data) \
                and form.password1.data == form.password2.data:
            # Correct input, now check database
            success = True
            user_by_username = User.query.filter_by(username=form.username.data).first()
            user_by_email = User.query.filter_by(email=form.email.data).first()
            if user_by_username:
                flash("Username  taken!", category='error')
                success = False
            if user_by_email:
                flash("Email taken!", category='error')
                success = False
            if success:
                userName = form.username.data
                # encUsername = EncryptMsg(userName)
                email = form.email.data
                # hashedEmail = FinnHash(email)
                password1 = form.password1.data
                hashedPassword = argon2.hash(password1)
                secret = pyotp.random_base32()
                user = User(username=userName, email=email, password=hashedPassword, token=secret, FA=False)
                db.session.add(user)
                db.session.commit()

                login_user(user)
                session['logged_in'] = True
                session['user'] = email
                session.permanent = True
                message = "Sign-up: User: " + str(userName) + ". Status sucess. Time: " + str(datetime.datetime.now())
                db.session.add(Logs(log=message))
                db.session.commit()
                return redirect(url_for('auth.two_factor_view'))
            else:
                message = "Sign-up: User: " + form.username.data + ". Status fail. Time: " + str(
                    datetime.datetime.now())
                db.session.add(Logs(log=message))
                db.session.commit()
                return render_template('signup.html', form=form)
        else:
            flash("Check your input", category='error')
    return render_template('signup.html', form=form)


@auth.route('/homelogin', methods=['GET'])
@login_required
def home_login():
    queried_from_user = User.query.filter_by(username=current_user.username).first()
    amount_in_database: int = queried_from_user.get_money()[0]
    transactions = queried_from_user.get_money()[1]
    return render_template('homelogin.html', current_user=current_user.username, saldo=amount_in_database,
                           transactions=transactions)


@auth.route('/atm', methods=['GET', 'POST'])
@login_required
def atm_transaction():
    form = ATMForm()
    if form.validate_on_submit():
        if validate_int(form.amount.data) and validate_username(form.username.data) and validate_int(form.OTP.data):

            amount = form.amount.data
            username = form.username.data
            success = True

            if amount < 1 or amount > 10_000:
                success = False
                flash('Amount needs to be between 1 and 10 000', category='error')
                return redirect(url_for('auth.atm_transaction'))


            user = User.query.filter_by(username=username).first()
            if not user:
                success = False
                flash(f"User with username {username} doesn't exist", category="error")
                return redirect(url_for('auth.atm_transaction'))


            if user and current_user.id != user.id:
                success = False
                flash("Can't transfer money from an account you don't own", category="error")
                return redirect(url_for('auth.atm_transaction'))


            otp = form.OTP.data
            if pyotp.TOTP(user.token).verify(otp) == False:
                success = False
                flash("Invalid OTP", category='error')
                return redirect(url_for('auth.atm_transaction'))


            if success:
                new_transaction = Transaction(to_user_id=username, in_money=amount)
                db.session.add(new_transaction)
                db.session.commit()
                message = "ATM deposit: User: " + username + ". Status: Sucess. Time: " + str(datetime.datetime.now())
                db.session.add(Logs(log=message))
                db.session.commit()
                return redirect(url_for('auth.home_login'))
            else:
                message = "ATM deposit: User: " + username + ". Status: Fail. Time: " + str(datetime.datetime.now())
                db.session.add(Logs(log=message))
                db.session.commit()
                return redirect(url_for('auth.atm_transaction'))

        else:
            flash("Invalid request", category='error')
            message = "ATM deposit: User: Invalid Input. Status: Fail. Time: " + str(datetime.datetime.now())
            db.session.add(Logs(log=message))
            db.session.commit()
            return redirect(url_for('auth.atm_transaction'))
            

    return render_template('atm.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash("You are already logged in")
        return redirect(url_for('auth.home_login'))
    form = LoginForm()
    if form.validate_on_submit():
        if validate_password(form.password.data) and validate_email(form.email.data) and validate_int(form.OTP.data):
            user = User.query.filter_by(email=form.email.data).first()
            otp = form.OTP.data
            if user is not None and argon2.verify(form.password.data, user.password) and pyotp.TOTP(
                    user.token).verify(otp):
                login_user(user)
                user.FA = True
                message = "Log-in: User: " + user.username + "Status: Success. Time: " + str(datetime.datetime.now())

                db.session.add(Logs(log=message))
                db.session.commit()
                session['logged_in'] = True
                message = "Log-in: User: " + user.username + "Status: Sucess. Time: " + str(datetime.datetime.now())
                db.session.add(Logs(log=message))
                db.session.commit()
                return redirect(url_for('auth.home_login'))
            flash("Email, Password or OTP does not match!", category="error")
            message = "Log-in: User: " + user.username + "Status: Fail. Time: " + str(datetime.datetime.now())
            db.session.add(Logs(log=message))
            db.session.commit()

            flash("Something went wrong. Please try again", category="error")
        else:
            flash("Invalid request", category='error')
            message = "Log-in: User: Invalid Input. Status: Fail. Time: " + str(datetime.datetime.now())
            db.session.add(Logs(log=message))
            db.session.commit()
    return render_template('login.html', form=form)

@login_required
@auth.route('/two_factor_setup', methods=['GET'])
def two_factor_view():
    try:
        secret = current_user.token
        if current_user.FA:
            return redirect(url_for('auth.home_login'))
        intizalize = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name='BankA250')
        return render_template('two-factor-setup.html', qr_link=intizalize)
    except:
        return redirect(url_for("views.home"))


@auth.route('/transaction', methods=['GET', 'POST'])
@login_required
def transaction():
    form = TransactionForm()
    if form.validate_on_submit():
        if validate_username(form.from_user_name.data) and validate_username(
                form.to_user_name.data) and validate_string(form.message.data) and validate_int(form.amount.data) and validate_int(form.OTP.data):
            amount = form.amount.data
            from_user_name = form.from_user_name.data
            to_user_name = form.to_user_name.data
            message = form.message.data

            success = True

            # Check if money amount is legal (between 1-200000)
            if amount < 1 or amount > 500_000:
                success = False
                flash("Money amount has to be a value between 1 and 500'000", category="error")
                return redirect(url_for('auth.transaction'))


            # From ID and To ID exist
            queried_from_user = User.query.filter_by(username=from_user_name).first()
            queried_to_user = User.query.filter_by(username=to_user_name).first()
            if not queried_from_user:
                success = False
                flash(f"User with username {from_user_name} doesn't exist", category="error")
                return redirect(url_for('auth.transaction'))

            if not queried_to_user:
                success = False
                flash(f"User with username {to_user_name} doesn't exist", category="error")
                return redirect(url_for('auth.transaction'))


            # Trying to send money to himself
            if queried_from_user and current_user.username == queried_to_user.username:
                success = False
                flash("Can't send money to yourself", category="error")
                return redirect(url_for('auth.transaction'))


            amount_in_database: int = queried_from_user.get_money()[0]
            if amount > amount_in_database:
                success = False
                flash(f"Not enough money to send you have {amount_in_database} and you tried to send {amount}",
                      category='error')
                return redirect(url_for('auth.transaction'))
                

            # Is logged in on "from ID"
            if queried_from_user and queried_to_user and \
                    (current_user.id != queried_from_user.id or current_user.username != queried_from_user.username):
                success = False
                flash("Can't transfer money from an account you don't own", category="error")
                return redirect(url_for('auth.transaction'))


            otp = form.OTP.data
            if pyotp.TOTP(queried_from_user.token).verify(otp) == False:
                success = False
                flash("Invalid OTP", category='error')
                return redirect(url_for('auth.transaction'))


            if not success:
                flash("Unsuccessful transaction", category="error")
                message = "Transaction: UserFrom-UserTo: " + queried_from_user.username + " " + queried_to_user.username + ". Status: Fail. Time: " + str(
                    datetime.datetime.now())
                db.session.add(Logs(log=message))
                db.session.commit()
                return render_template('transaction.html', form=form)

            new_transaction = Transaction(out_money=amount, from_user_id=from_user_name, to_user_id=to_user_name,
                                          in_money=amount, message=message)
            db.session.add(new_transaction)
            db.session.commit()
            message = "Transaction: UserFrom-UserTo: " + queried_from_user.username + "-" + queried_to_user.username + ". Status: Sucess. Time: " + str(
                datetime.datetime.now())
            db.session.add(Logs(log=message))
            db.session.commit()

            return redirect(url_for('auth.home_login'))
        else:
            flash("Invalid request", category='error')
            return redirect(url_for('auth.home_login'))

    return render_template('transaction.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    message = "Logout: User: " + current_user.username + ". Status: Sucess. Time: " + str(datetime.datetime.now())
    db.session.add(Logs(log=message))
    db.session.commit()
    logout_user()
    session['logged_in'] = False
    session.clear()
    return redirect(url_for('auth.login'))


def validate_password(password):
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

    if bigLetter == 0 or smallLetter == 0 or number == 0 or illegal != 0 or sum < 11 or sum > 200:
        return False
    return True


def validate_username(username):
    if len(username) < 2 or len(username) > 50:
        flash("Username must be longer than one character, and shorter than fifty", category='error')
        return False

    # If only contains small and big letters
    if re.search("^[a-zA-Z0-9s]+$", username):
        return True
    flash("Username can only contain letters and numbers", category='error')
    return False


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
        flash("Email must be longer than two character, and shorter than fifty", category='error')
        return False

    check = 0
    for letter in email:
        try:
            ord(letter)
            if ord(letter) == 64:
                check += 1

        except:
            flash("Email must consists of legal characters", category='error')
            return False
    return True


