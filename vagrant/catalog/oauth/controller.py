from flask import (request,
                   url_for,
                   abort,
                   g,
                   render_template,
                   redirect)
from flask import Blueprint
from models import Base, User, Category, Item
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, exc
import random
import string
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
                open('client_secrets.json', 'r').read()
            )['web']['client_id']
FB_APP_ID = json.loads(
        open('fb_client_secrets.json', 'r').read()
    )['web']['app_id']
FB_APP_SECRET = json.loads(
        open('fb_client_secrets.json', 'r').read()
    )['web']['app_secret']

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

oauth = Blueprint('oauth', __name__)


def getUserID(email):
    session = DBSession()
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except exc.SQLAlchemyError:
        return None


def getUserInfo(user_id):
    session = DBSession()
    user = session.query(User).filter_by(id=user_id)
    return user


def createUser(login_session):
    session = DBSession()
    newUser = User(
        username=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
    )
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(
        email=login_session['email']).one_or_none()
    return user.id


@oauth.route('/fbconnect', methods=['POST'])
def fbconnect():
    """
    The connect flow is:
    0. Check if the session token matched, if not then abandon.
    1. Get access token from FE.
    2. Exchange access token with FB.
    3. Use the exchanged token to get user's info.
    4. Store user's info in session.
    5. Create the user data in DB if necessary.
    """

    session = DBSession()
    # CSRF protection
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    # Exchange access token with FB
    url = 'https://graph.facebook.com/oauth/access_token?' \
        'grant_type=fb_exchange_token&client_id=%s&client_secret=%s&' \
        'fb_exchange_token=%s' % (FB_APP_ID, FB_APP_SECRET, access_token)

    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user's name, id and email from API
    '''
    Due to the formatting for the result from the server token
    exchange we have to split the token first on commas and select the
    first index which gives us the key : value for the server access
    token then we split it on colons to pull out the actual token value
    and replace the remaining quotes with nothing so that it can be used
    directly in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?' \
        'access_token=%s&fields=name,id,email' % token

    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?' \
        'access_token=%s&redirect=0&height=200&width=200' % token

    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if user_id is None:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # return a welcome page to FE
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: ' \
        '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;">'

    return output


@oauth.route('/gconnect', methods=['POST'])
def gconnect():
    """
    The connect flow is:
    0. Check if the session token matched, if not then abandon.
    1. Get authorization code from FE.
    2. Exchange the authorization code with Google for
    credential (including access token).
    3. If the access token is not valid, abort.
    4. If the access token is not for this user, abort.
    5. If the access token is not for this app, abort.
    6. Get user info using access token.
    7. Store user's info in session.
    8. Create the user data in DB if necessary.
    """

    session = DBSession()
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    login_session['access_token'] = access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session['access_token']
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200
        )
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if user_id is None:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # return a welcome page to FE
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: ' \
        '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;">'

    return output


@oauth.route('/fbdisconnect')
def fbdisconnect():
    """
    The disconnection flow is:
    1. Get the facebook id and access token
    2. Send a DELETE request to FB API
    3. If successful, delete all the sessions
    4. If failed, do not delete the session
    """

    session = DBSession()
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
        % (facebook_id, access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'DELETE')[1])
    if 'success' in result and result['success'] is True:
        del login_session['access_token']
        del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        del login_session['user_id']
        return redirect(url_for('showLatest'))
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400)
        )
        response.headers['Content-Type'] = 'application/json'
        return response


@oauth.route('/gdisconnect')
def disconnect():
    """
    The disconnection flow is:
    1. Get the access token
    2. Send a GET request to Google API
    3. If successful, delete all the sessions
    4. If failed, do not delete the session
    """

    session = DBSession()
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401
        )
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
        % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        del login_session['user_id']
        return redirect(url_for('showLatest'))
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400)
        )
        response.headers['Content-Type'] = 'application/json'
        return response


@oauth.route('/logout')
def logout():
    if login_session['provider'] == 'google':
        return disconnect()
    elif login_session['provider'] == 'facebook':
        return fbdisconnect()


@oauth.route('/login')
def showLogin():
    session = DBSession()
    state = ''.join(
        random.choice(string.ascii_uppercase+string.digits) for x in xrange(32)
    )
    login_session['state'] = state
    # dynamically render the google and facebook app id in FE page.
    return render_template(
        'login.html',
        state=state,
        hideLogin=True,
        g_client_id=CLIENT_ID,
        fb_app_id=FB_APP_ID
    )