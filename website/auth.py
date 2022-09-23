from flask import Blueprint, render_template, request, flash, redirect, url_for
from . import db
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('The user or password are not correct.', category='error')
        else:
            flash('The user or password are not correct.', category='error')
    return render_template('login.html', user=current_user)

@auth.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        lastName = request.form.get('lastName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('This user is already registered.', category='error')
        elif len(email) < 4:
            flash('El email debe ser de, al menos, 4 caracteres.', category='error')
        elif len(firstName) < 2:
            flash('El primer nombre debe ser de, al menos, 2 caracteres.', category='error')
        elif len(lastName) < 2:
            flash('El apellido debe ser de, al menos, 2 caracteres.', category='error')
        elif len(password1) < 7:
            flash('La contraseña debe ser de, al menos, 7 caracteres.', category='error')
        elif password1 != password2:
            flash('Por favor, confirme su contraseña correctamente.', category='error')
        else:
            new_user = User(
                email = email,
                password = generate_password_hash(password1, method='sha256'),
                first_name = firstName,
                last_name = lastName
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)
            flash('Account created successfully!', category='success')
            return redirect(url_for('views.home'))

    return render_template('signup.html', user=current_user)

