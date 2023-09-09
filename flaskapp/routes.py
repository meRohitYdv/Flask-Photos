import os
import secrets
import base64
from PIL import Image
from flask import render_template, Flask, url_for, flash, redirect, request, jsonify, session
from flaskapp import app, db, bcrypt, jwt, limiter
from flaskapp.models import User, Photo
from flaskapp.forms import RegistrationForm, LoginForm, UpdateAccountForm, UploadPhotoForm
from flask_login import login_user, logout_user, login_required
from flask_jwt_extended import jwt_required, create_access_token, decode_token
from functools import wraps
from datetime import timedelta

def is_logged_in():
    try:
        token = request.cookies.get('flask_photos_access_token')
        decoded_token = decode_token(token)
    except Exception as e:
        return False
    return True


def protected_route(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        try:
            token = request.cookies.get('flask_photos_access_token')
            decoded_token = decode_token(token)
            session['user'] = decoded_token.get('sub')
        except Exception as e:
            return redirect(url_for('login'))
        
        return view_func(*args, **kwargs)
    return wrapper

def save_photo(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/photos', picture_fn)
    form_picture.save(picture_path)
    return picture_fn

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@protected_route
def home():
    form = UploadPhotoForm()
    if form.validate_on_submit():
        picture_file = save_photo(form.picture.data)

        user = User.query.filter_by(email=session.get('user').get('email')).first()
        photo = Photo(photo=picture_file, title=form.title.data, user_id=user.id)
        db.session.add(photo)
        db.session.commit()
        flash('Your photo has been uploaded!', 'success')
        return redirect(url_for('my_photos'))
    elif (request.method == 'GET' and not form.title.data) and form.picture.data:
        form_picture = form.picture.data
        root_ext = os.path.splitext(form_picture.filename)
        form.title.data = root_ext[0]
    
    return render_template('home.html', form=form, is_logged_in=is_logged_in)

@app.route('/my-photos')
@limiter.limit("5 per minute")
@protected_route
def my_photos():
    user_id = User.query.filter_by(email=session.get('user').get('email')).first().id
    uploaded_photos = Photo.query.filter_by(user_id=user_id).all()
    uploaded_photos = sorted(uploaded_photos, key=lambda photo: photo.date_posted, reverse=True)
    return render_template('my-photos.html', title='my photos', uploaded_photos=uploaded_photos, is_logged_in=is_logged_in)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if is_logged_in():
        return redirect(url_for('home'))

    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form, is_logged_in=is_logged_in)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if is_logged_in():
        return redirect(url_for('home'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            user_info = { 'username': user.username, 'email': user.email, 'image_file': user.image_file }
            access_token = create_access_token(identity=user_info, expires_delta=timedelta(minutes=60))
            next_page = request.args.get('next')
            response = redirect(next_page) if next_page else redirect(url_for('home'))
            response.set_cookie('flask_photos_access_token', access_token, secure=True, httponly=True)
            return response
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    if(request.args.get('next')):
        flash('Please Login to access this page', 'success')
    return render_template('login.html', title='Login', form=form, is_logged_in=is_logged_in)


@app.route('/logout')
@limiter.limit("5 per minute")
def logout():
    response = redirect(url_for('home'))
    response.set_cookie('flask_photos_access_token', '', expires=0)
    return response

def save_profile_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    
    return picture_fn

@app.route('/account', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@protected_route
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        user_to_update = db.session.query(User).filter_by(email=form.email.data).first()
        if form.picture.data:
            picture_file = save_profile_picture(form.picture.data)
            user_to_update.picture_file = picture_file
            session['user']['image_file'] = picture_file
        
        user_to_update.email = session.get('user').get('email')
        user_to_update.password = session.get('user').get('password')
        db.session.commit()
        session['user']['username'] = form.username.data
        session['user']['email'] = form.email.data
        access_token = create_access_token(identity=user_info, expires_delta=timedelta(minutes=60))
            
        flash('Your account has been updated!', 'success')
        response = redirect(url_for('account'))
        response.set_cookie('flask_photos_access_token', access_token, secure=True, httponly=True)
        return response
         
    elif request.method == 'GET':
        form.username.data = session.get('user').get('username')
        form.email.data = session.get('user').get('email')
    image_file = url_for('static', filename='profile_pics/' + session.get('user').get('image_file'))
    return render_template('account.html', title='Account', 
                            image_file=image_file, form=form, is_logged_in=is_logged_in)

photos_folder = os.path.join(app.root_path, 'photos')

@app.route('/upload_from_device', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@protected_route
def upload_from_device():
    if 'image' in request.files:
        uploaded_image = request.files['image']
        if uploaded_image.filename != '':
            picture_file = save_photo(uploaded_image)

            user = User.query.filter_by(email=session.get('user').get('email')).first()
            photo = Photo(photo=picture_file, title="Captured Image", user_id=user.id)
            db.session.add(photo)
            db.session.commit()
            flash('Your photo has been uploaded!', 'success')
            return 'Image uploaded successfully'
    return render_template('upload_from_device.html', title='Upload From Device', is_logged_in=is_logged_in)
