import os

import sys



import click

from flask import Flask, request, g, session, redirect, url_for, render_template, jsonify, flash

from flask_github import GitHub

from flask_sqlalchemy import SQLAlchemy



# sqlite URI compatible

WIN = sys.platform.startswith('win')

if WIN:

    prefix = 'sqlite:///'

else:

    prefix = 'sqlite:////'



app = Flask(__name__)

app.jinja_env.trim_blocks = True

app.jinja_env.lstrip_blocks = True



app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret string')

# Flask-SQLAlchemy

#app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', prefix + os.path.join(app.root_path, 'data.db'))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'data.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#

# Register your OAuth application on https://github.com/settings/applications/new

# Just test, better to save this values as enviroment variable

app.config['GITHUB_CLIENT_ID'] = '20d69d4fcfb09833e7ab'

app.config['GITHUB_CLIENT_SECRET'] = '3e47273cfe1709c381610f19d7e16d9ca87c3457'

db = SQLAlchemy(app)
db.create_all()

github = GitHub(app)





@app.cli.command()

@click.option('--drop', is_flag=True, help='Create after drop.')

def initdb(drop):

    """Initialize the database."""

    if drop:

        db.drop_all()

    db.create_all()

    click.echo('Initialized database.')




# Model store user info
class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100))

    access_token = db.Column(db.String(200))





@app.before_request

def before_request():

    g.user = None

    if 'user_id' in session:

        g.user = User.query.get(session['user_id']) #if log in save in g





@app.route('/')
#index page
def index():

    if g.user: # if log in

        is_login = True

        response = github.get('user')

        avatar = response['avatar_url']

        username = response['name']

        url = response['html_url']

        return render_template('index.html', is_login=is_login, avatar=avatar, username=username, url=url)

    is_login = False

    return render_template('index.html', is_login=is_login) #deal with index.html




@github.access_token_getter

def token_getter():

    user = g.user

    if user is not None:

        return user.access_token




@app.route('/callback/github')#match with github callback uri
#if authorized, will send a Post message, with ID, Keys, Code and redirect_uri and Access Token.

@github.authorized_handler

def authorized(access_token):

    if access_token is None:

        flash('Login failed.')

        return redirect(url_for('index'))

    response = github.get('user', access_token=access_token)#Get username on github

    username = response['login']  # get username

    user = User.query.filter_by(username=username).first() #if the user exist, if not, save in session

    if user is None:

        user = User(username=username, access_token=access_token)

        db.session.add(user)

    user.access_token = access_token  # update access token

    db.session.commit()

    flash('Login success.')

    # log the user in

    session['user_id'] = user.id

    return redirect(url_for('index'))

#@github.access_token_getter
#def token_getter():
    #user = g.user
    #if user is not None:
        #return user.access_token



@app.route('/login')

def login():

    if session.get('user_id', None) is None:

        return github.authorize(scope='repo')

    flash('Already logged in.')

    return redirect(url_for('index'))





@app.route('/logout')

def logout():

    session.pop('user_id', None)

    flash('Goodbye.')

    return redirect(url_for('index'))





@app.route('/user')

def get_user():

    return jsonify(github.get('user'))
