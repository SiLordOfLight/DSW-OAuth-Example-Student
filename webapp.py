from flask import Flask, redirect, url_for, session, request, jsonify, flash
from flask_oauthlib.client import OAuth
from flask import render_template

import pprint
import os

# This code originally from https://github.com/lepture/flask-oauthlib/blob/master/example/github.py
# Edited by P. Conrad for SPIS 2016 to add getting Client Id and Secret from
# environment variables, so that this will work on Heroku.
# Edited by S. Adams for Designing Software for the Web to add comments and remove flash messaging

app = Flask(__name__)

app.debug = True #Change this to False for production

app.secret_key = os.environ['SECRET_KEY']
oauth = OAuth(app)
oauth.init_app(app)

os.environ['OAUTHLIB_INSECURE_TRANSPORT']='1'

github = oauth.remote_app(
    'github',
    consumer_key=os.environ['GITHUB_CLIENT_ID'],
    consumer_secret=os.environ['GITHUB_CLIENT_SECRET'],
    request_token_params={'scope': 'user:email'}, #request read-only access to the user's email.  For a list of possible scopes, see developer.github.com/apps/building-oauth-apps/scopes-for-oauth-apps
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize' #URL for github's OAuth login
)


@app.context_processor
def inject_logged_in():
    return {"logged_in":('github_token' in session)}

@app.route('/')
def home():
    if "do_flash" not in session:
        session["do_flash"] = False
        session["flash_message"] = ""
        session["flash_mode"] = ""

    if session["do_flash"]:
        flash(session["flash_message"],session["flash_mode"])
        session["do_flash"] = False
        session["flash_message"] = ""
        session["flash_mode"] = ""
    return render_template('home.html')

@app.route('/login')
def login():
    return github.authorize(callback=url_for('authorized', _external=True, _scheme='http'))

@app.route('/logout')
def logout():
    session.clear()
    session["do_flash"] = True
    session["flash_message"] = "You were logged out"
    session["flash_mode"] = "warning"
    return redirect(url_for('.home'))

@app.route('/login/authorized')#the route should match the callback URL registered with the OAuth provider
def authorized():
    resp = github.authorized_response()
    if resp is None:
        session.clear()
        message = 'sthAccess denied: reason=' + request.args['error'] + ' error=' + request.args['error_description'] + ' full=' + pprint.pformat(request.args)
        session["do_flash"] = True
        session["flash_message"] = message
        session["flash_mode"] = "danger"
    else:
        try:
            session['github_token'] = (resp['access_token'], '')
            session['user_data'] = github.get('user').data
            message = "Congratulations, %s, you were successfully logged in!" % session['user_data']['login']
            session["do_flash"] = True
            session["flash_message"] = message
            session["flash_mode"] = "success"
        except:
            session.clear()
            message = "Login could not be completed. Please try again later. \u2639"
            session["do_flash"] = True
            session["flash_message"] = message
            session["flash_mode"] = "warning"
    return redirect(url_for('.home'))


@app.route('/page1')
def renderPage1():
    if 'user_data' in session:
        user_data_pprint = pprint.pformat(session['user_data'])#format the user data nicely
    else:
        user_data_pprint = '';
    return render_template('page1.html',dump_user_data=user_data_pprint)

@app.route('/page2')
def renderPage2():
    if 'user_data' in session:
        return render_template('page2.html', content=session['user_data']['public_repos'])
    else:
        return redirect(url_for('.login'))


@github.tokengetter
def get_github_oauth_token():
    return session.get('github_token')


if __name__ == '__main__':
    app.run()
