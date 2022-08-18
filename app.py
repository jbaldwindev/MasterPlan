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

#planner id is represented as title_username
class Planner(db.Model):
    __tablename__ = 'planners'
    plannerID = db.Column(db.String(61), primary_key=True)
    plannerTitle = db.Column(db.String(40), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f"Planner: { self.plannerID, self.plannerTitle, self.description, self.username }"

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
                        return render_template('login.html', not_found='Username or password is incorrect')
    return render_template('login.html')

@app.route("/logout")
def logout_page():
    if 'user' in session:
        session.pop('user', None)
    return redirect('/')

@app.route("/planners")
def planner_page():
    if 'user' in session:
        currentUser = session['user']
        plannerList = db.session.query(Planner).filter(Planner.username == currentUser).all()
        styledList = ''
        if (plannerList):
            for planner in plannerList:
                styledList = styledList + '<div>' + planner.plannerTitle + '</div>'
            return render_template('planners.html', planners=styledList)
        return render_template('planners.html')
    else:
        return redirect('/signup')

@app.route('/create-planner', methods=['POST'])
def newPlannerRoute():
    if 'user' in session and request.method == 'POST':
        title = request.form['title']
        description = request.form['desc']
        potentialID = title + '_' + session['user']
        potentialPlanner = db.session.query(Planner).get(potentialID)
        if potentialPlanner:
            #TODO find way to reroute and also display error to user
            #maybe using optional parameters through url
            print("error: planner with that title already exists")
            redirect('/planners')
        elif title and description:
            createPlanner(session['user'], title, description)
            return redirect('/planners')
    else:
        return redirect('/signup')

#database functions
def createUser(user, pswd):
    newUser = User(username = user, password = pswd)
    db.session.add(newUser)
    db.session.commit()

def createPlanner(username, title, description):
    id = title + '_' + username
    newPlanner = Planner(plannerID = id, plannerTitle = title, description = description, username = username)
    db.session.add(newPlanner)
    db.session.commit()