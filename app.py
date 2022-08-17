from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, migrate
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)

#TODO remember to hide these before pushing
app.config['SQLALCHEMY_DATABASE_URI'] = 'secret'
app.secret_key = b'secret'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(20), primary_key=True)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"Username: { self.username, self.password }"

@app.route("/")
def main():
    if 'user' in session:
        return render_template('main.html', signed_in='yes')
    else:
        return render_template('main.html')

@app.route("/signup", methods=['GET', 'POST'])
def signup_page():
    if 'user' in session:
        return redirect('/')
    if request.method == 'POST':
        user = request.form['username']
        pswd = request.form['psw']
        retypedPswd = request.form['psw-repeat']
        if user and pswd and retypedPswd and pswd == retypedPswd:
            userInfo = db.session.query(User).get(user)
            if userInfo:
                return render_template('signup.html', error='Username already taken')
            hashpass = pbkdf2_sha256.encrypt(pswd, rounds=200000, salt_size=16)
            createUser(user, hashpass)
            return redirect("/login")
        else:
            return render_template('signup.html', error='Must complete full form')
    return render_template('signup.html')

#TODO add message for people who just signed up that says "account successfully created"
@app.route("/login", methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        if 'user' in session:
            return redirect('/')
        else:
            user = request.form['username']
            pswd = request.form['psw']
            if user and pswd:
                userInfo = db.session.query(User).get(user)
                if userInfo:
                    if pbkdf2_sha256.verify(pswd, userInfo.password):
                        session['user'] = user
                        return redirect('/')
                    else:
                        return render_template('login.html', not_found='Sign in failed')
                else:
                        return render_template('login.html', not_found='Sign in failed')
    return render_template('login.html')

@app.route("/logout")
def logout_page():
    if 'user' in session:
        session.pop('user', None)
    return redirect('/')

def createUser(user, pswd):
    newUser = User(username = user, password = pswd)
    db.session.add(newUser)
    db.session.commit()