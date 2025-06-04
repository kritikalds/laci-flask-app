from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ez_egy_very_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    admin = db.Column(db.Boolean, default=False)

class Appointment(db.Model):
    __tablename__ = 'appointments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # idegen kulcs!
    date_time = db.Column(db.DateTime, unique=True, nullable=False)

    user = db.relationship('User', backref='appointments')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Nézetek ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('appointments'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']  # új mező a regisztrációs űrlapon
        if User.query.filter_by(email=email).first():
            flash('Ez az email már regisztrálva van.', 'danger')
            return redirect(url_for('register'))
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(name=name, email=email, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Sikeres regisztráció! Jelentkezz be.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('appointments'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('appointments'))
        else:
            flash('Sikertelen bejelentkezés, ellenőrizd az adatokat.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/appointments', methods=['GET', 'POST'])
@login_required
def appointments():
    if request.method == 'POST':
        date_time_str = request.form['date_time']  # pl. '2025-06-05 14:00'
        try:
            date_time = datetime.strptime(date_time_str, '%Y-%m-%d %H:%M')
        except ValueError:
            flash('Hibás időpont formátum. Használd: ÉÉÉÉ-HH-NN ÓÓ:PP', 'danger')
            return redirect(url_for('appointments'))

        if Appointment.query.filter_by(date_time=date_time).first():
            flash('Ez az időpont már foglalt.', 'danger')
        else:
            appointment = Appointment(user_id=current_user.id, date_time=date_time)
            db.session.add(appointment)
            db.session.commit()
            flash('Időpont sikeresen lefoglalva!', 'success')

    # Lekérjük az összes időpontfoglalást, és előtöltjük a user adatokat
    appointments = Appointment.query.join(User).add_entity(User).all()
    # appointments most lista lesz: [(Appointment objektum, User objektum), ...]

    # Kényelmesebben a sablonba küldhetjük csak a Appointment objektumokat, mert van user kapcsolat
    # így ez is működik: appointments = Appointment.query.all()
    # A sablonban meg hívjuk app.user.name-t

    appointments = Appointment.query.order_by(Appointment.date_time).all()

    return render_template('appointments.html', appointments=appointments)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
