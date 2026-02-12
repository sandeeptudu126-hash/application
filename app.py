from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------
# App Configuration
# -----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extra Security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)

# -----------------------
# Login Manager
# -----------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# -----------------------
# Database Model
# -----------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------
# Forms (Validation + CSRF)
# -----------------------
class RegisterForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(),
        Length(min=4, max=20)
    ])
    email = StringField(validators=[
        InputRequired(),
        Email()
    ])
    password = PasswordField(validators=[
        InputRequired(),
        Length(min=6)
    ])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired()])
    password = PasswordField(validators=[InputRequired()])
    submit = SubmitField("Login")

# -----------------------
# Routes
# -----------------------

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():

        # Check if user already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already exists!")
            return redirect("signup.html")

        # Hash password
        hashed_password = generate_password_hash(form.password.data)

        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! Please login.")
        return redirect("login.html")

    return render_template("signup.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect("dashboard.html")
        else:
            flash("Invalid username or password")

    return render_template("login.html", form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully")
    return redirect('home')

# -----------------------
# Run Application
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False)

