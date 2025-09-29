import re
from flask import Flask, flash, json, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
import requests
from sqlalchemy import exc
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user

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
    if current_user.is_authenticated:
        return redirect(url_for('create'))
    else:
        return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if current_user.is_authenticated:
        return redirect(url_for('create'))

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
        return redirect(url_for('create'))

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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Successfully Logged Out", 'success')
    return redirect(url_for('home'))

@app.route('/create', methods=['GET', 'POST'])
def create():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'GET':
        return render_template('create.html')
    if request.method == 'POST':
        prompt = request.form.get('prompt')

        url = "https://ai.hackclub.com/chat/completions"

        data = {
            "model": "gpt-4o-mini",
            "messages": [

                {"role": "system", "content": "you are a helpful assistant that gives ten, four choices flashcard questions to users, if they don't specify a known subject or something unclear please tell them so AND ONLY outputs JSON with exactly this structure: {\"questions\": [{\"question\": \"...\", \"choices\": [\"...\",\"...\",\"...\",\"...\"], \"answer\": \"...\"}]} Do not include explanations, markdown, or any extra text.."},

                {"role": "user", "content": prompt}
            ]
        }

        response = requests.post(url, json=data)
        ai_reply = response.json()["choices"][0]["message"]["content"].strip()

        json_match = re.search(r'\{.*\}', ai_reply, re.DOTALL)
        if json_match:
            ai_reply = json_match.group(0)

        try:
            flashcards = json.loads(ai_reply)
        except Exception as e:
            flashcards = {"error": "AI did not return valid JSON", "raw": ai_reply}

        return render_template('create.html', flashcards=flashcards)


# RUNNING

if __name__ == '__main__':
    app.run(debug=True)