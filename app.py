
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, migrate
from passlib.hash import pbkdf2_sha256

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'Is a secret'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(20), primary_key=True)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"Username: { self.username, self.password }"

@app.route("/", methods=['GET', 'POST'])
def main():
    if request.method == 'POST':
        user = request.form['username']
        pswd = request.form['psw']
        retypedPswd = request.form['psw-repeat']
        if user and pswd and retypedPswd and pswd == retypedPswd:
            hashpass = pbkdf2_sha256.encrypt(pswd, rounds=200000, salt_size=16)
            createUser(user, hashpass)
            return redirect("/login")
        else:
            return redirect("/")
    return render_template('signup.html')

@app.route("/login")
def login_page():
    return render_template('login.html')

def createUser(user, pswd):
    newUser = User(username = user, password = pswd)
    db.session.add(newUser)
    db.session.commit()