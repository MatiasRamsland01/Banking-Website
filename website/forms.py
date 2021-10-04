from itertools import count
from flask_wtf import FlaskForm, recaptcha
from flask_wtf.recaptcha.fields import RecaptchaField
from flask_wtf.recaptcha.validators import Recaptcha
from sqlalchemy.sql.expression import label
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms import validators
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash


class RegisterForm(FlaskForm):
    nameFirst = StringField(label='First Name:', validators=[DataRequired(), Length(min=2, max=30,
                                                                                    message="First Name must be between 2 and 30 characters!")])

    nameLast = StringField(label='Last Name:', validators=[DataRequired(), Length(min=2, max=30,
                                                                                  message="Last Name must be between 2 and 30 characters!")])
    email = StringField(label='Email:', validators=[Email()])
    password1 = PasswordField(label='Password:', validators=[DataRequired(), Length(min=7, max=100,
                                                                                    message="Password must be between 7 and 100 characters!")])
    password2 = PasswordField(label='Confirm Password',
                              validators=[DataRequired(), EqualTo('password1', message="Passwords don't match!")])
    recaptcha = RecaptchaField()
    submit = SubmitField(label='Create Account')

    # Checks if name does not contain any special letters
    def validate_nameFirst(self, nameFirst):
        counter = 0
        message = "You can't use special characters in your name"
        # Might be a whacky soloution but works for now
        for letter in nameFirst.data:
            if ord(letter) >= 65 and ord(letter) <= 90 or ord(letter) >= 97 and ord(letter) <= 122:
                counter += 1
        if counter != len(nameFirst.data):
            raise ValidationError(message)

    def validate_nameLast(self, nameFirst):
        counter = 0
        message = "You can't use special characters in your name"
        # Might be a whacky soloution but works for now
        for letter in nameFirst.data:
            if ord(letter) >= 65 and ord(letter) <= 90 or ord(letter) >= 97 and ord(letter) <= 122:
                counter += 1
        if counter != len(nameFirst.data):
            raise ValidationError(message)

    # Checks if password contains digits, small and big letters.
    def validate_password1(self, password1):
        bigLetter = 0
        smallLetter = 0
        number = 0
        illegal = 0
        for letter in password1.data:
            if ord(letter) >= 48 and ord(letter) <= 57:
                number += 1
            elif ord(letter) >= 97 and ord(letter) <= 122:
                smallLetter += 1
            elif ord(letter) >= 65 and ord(letter) <= 90:
                bigLetter += 1
            else:
                illegal += 1
        # Could tell the user what is missing and not just list everything. Might implement this later. It is just to add more if statements
        if bigLetter == 0 or smallLetter == 0 or number == 0 or illegal != 0:
            raise ValidationError("Your password must contain digits, small, big letters and no illegal characters.")


class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[Email()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=7, max=100,
                                                                                  message="Password must be between 7 and 100 characters!")])
    recaptcha = RecaptchaField()
    submit = SubmitField(label='Log in')


class TransactionForm(FlaskForm):
    amount = IntegerField(label='Choose your desired amount', validators=[DataRequired(),
                                                                          validators.NumberRange(min=1, max=10,
                                                                                                 message="THe amount must be between 0 and ")])  # Max need to change
    to = StringField(label='Username', validators=[DataRequired()])
    kid = StringField(label='Username')
    message = StringField(label='Message')
    submit = SubmitField(label='Transfer Money')

class VerifyForm(FlaskForm):
    OTP = StringField(label="Your one time password", validators=[DataRequired()])
    submit = SubmitField(label="Verify")
