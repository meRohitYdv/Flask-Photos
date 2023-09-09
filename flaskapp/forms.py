from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flaskapp.models import User
from flask import session

class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', 
                validators=[DataRequired(), Email()])
    password = PasswordField('Password', 
                validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', 
                validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user: 
            raise ValidationError('That username is taken. Please choose a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user: 
            raise ValidationError('That email is taken. Please choose a different email.')


class LoginForm(FlaskForm):
    email = StringField('Email', 
                validators=[DataRequired(), Email()])
    password = PasswordField('Password', 
                validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', 
                validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', 
                validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != session.get('user').get('username'):
            user = User.query.filter_by(username=username.data).first()
            if user: 
                raise ValidationError('That username is taken. Please choose a different username.')

    def validate_email(self, email):
        if email.data != session.get('user').get('email'):
            user = User.query.filter_by(email=email.data).first()
            if user: 
                raise ValidationError('That email is taken. Please choose a different email.')


class UploadPhotoForm(FlaskForm):
    title = StringField('Photo Title', 
                validators=[DataRequired(), Length(min=2, max=100)])
    picture = FileField('Photo', validators=[DataRequired(), FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Upload')