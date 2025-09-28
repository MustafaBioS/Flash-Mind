from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user

# INITIALIZATION

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['SECRET_KEY'] = 'FLASHMIND'

db = SQLAlchemy(app)

migrate = Migrate(app, db)

bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# DB MODELS

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key= True)
    username = db.Column(db.String(64), nullable=False)
    password = db.Column(db.Text, nullable=False)

# ROUTES

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('signup.html')
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            cpass = request.form.get('cpassword')

            if password == cpass:
                hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

                new_user = Users(username=username, password=hashed_pw)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                flash("Account Created Successfully", 'success')
                return redirect(url_for('home'))
            else:
                flash("Passwords Do Not Match", 'danger')
                return redirect(url_for('signup'))
        except exc.SQLAlchemyError:
            flash("Username Already Taken", 'danger')
            return redirect(url_for('signup'))


@app.route('/login', methods=['GET', 'POST'])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'GET':
        return render_template('login.html')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = Users.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Successfully Logged In", 'success')
            return redirect(url_for('home'))
        else:
            flash("Incorrect Credentials", 'danger')
            return redirect(url_for('login'))


@app.route('/create', methods=['GET', 'POST'])
def create():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'GET':
        return render_template('create.html')
    if request.method == 'POST':
        pass


# RUNNING

if __name__ == '__main__':
    app.run(debug=True)