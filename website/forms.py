from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms import validators
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash


class RegisterForm(FlaskForm):
  nameFirst = StringField(label='First Name:', validators=[DataRequired(), Length(min=2, max=30, message="First Name must be between 2 and 30 characters!")])
  nameLast = StringField(label='Last Name:', validators=[DataRequired(), Length(min=2, max=30, message="Last Name must be between 2 and 30 characters!")])
  email = StringField(label='Email:', validators=[Email()])
  password1 = PasswordField(label='Password:', validators=[DataRequired(), Length(min=7, max=100, message="Password must be between 7 and 100 characters!")])
  password2 = PasswordField(label='Confirm Password', validators=[DataRequired(), EqualTo('password1', message="Passwords don't match!")])
  submit = SubmitField(label='Create Account')


class LoginForm(FlaskForm):
  email = StringField(label='Email', validators=[Email()])
  password = PasswordField(label='Password', validators=[DataRequired(), Length(min=7, max=100, message="Password must be between 7 and 100 characters!")])
  submit = SubmitField(label='Log in')


class TransactionForm(FlaskForm):
  amount = IntegerField(label='Choose your desired amount', validators=[DataRequired(), validators.NumberRange(min=1, max=10, message="THe amount must be between 0 and ")]) #Max need to change
  to = StringField(label='Username', validators=[DataRequired()])
  submit = SubmitField(label='Transfer Money')
