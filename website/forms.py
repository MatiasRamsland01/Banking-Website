from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegisterForm(FlaskForm):
  nameFirst = StringField(label='First Name:', validators=[DataRequired(), Length(min=2, max=30, message="First Name must be between 2 and 30 characters!")])
  nameLast = StringField(label='Last Name:', validators=[DataRequired(), Length(min=2, max=30, message="Last Name must be between 2 and 30 characters!")])
  email = StringField(label='Email:', validators=[Email()])
  password1 = PasswordField(label='Password:', validators=[DataRequired(), Length(min=7, max=100, message="Password must be between 7 and 100 characters!")])
  password2 = PasswordField(label='Confirm Password', validators=[DataRequired(), EqualTo('password1', message="Passwords don't match!")])
  submit = SubmitField(label='Create Account')