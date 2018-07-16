from models import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for, abort, g, render_template, redirect, flash
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from flask import session as login_session
import random, string

# from flask.ext.httpauth import HTTPBasicAuth (flask.ext.httpauth is deprecated,)
from flask_httpauth import HTTPBasicAuth

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

auth = HTTPBasicAuth()
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

#ADD @auth.verify_password decorator here
@auth.verify_password
def verify_passowrd(username_or_token, password):
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        # if token is provided and passed
        user = session.query(User).filter_by(id = user_id).one()
    else:
        # if not passed, use username:password verification instead
        user = session.query(User).filter_by(username = username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/users', methods = ['POST'])
def createUser():
    session = DBSession()
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)
    user = session.query(User).filter_by(username = username).first()
    if user is not None:
        abort(400)
    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({'username': user.username}), 201

@app.route('/tokens', methods = ['POST'])
@auth.login_required
def getToken():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})
    
@app.route('/categories.json')
@auth.login_required
def showJSON():
    session = DBSession()
    jsonfile = {
        'result': 'success'
    }
    categories = session.query(Category).all()
    data = []
    for cate in categories:
        items = session.query(Item).filter_by(category_name = cate.name).all()
        jsonfile = {
            'id': cate.id,
            'name': cate.name,
            'item': [i.serialize for i in items]
        }
        data.append(jsonfile)
    return jsonify(Category=data)

@app.route('/')
@app.route('/categories')
def showLatest():
    session = DBSession()
    categories = session.query(Category).all()
    items = session.query(Item).order_by("id desc").all()   # list the latest itmes chronologically
    return render_template('showLatest.html', categories = categories, items = items, isLoggedIn = isLoggedIn(login_session))
    
@app.route('/categories/<string:category_name>')
@app.route('/categories/<string:category_name>/items')
def showCategoryItems(category_name):
    session = DBSession()
    categories = session.query(Category).all()
    items = session.query(Item).filter_by(category_name = category_name).order_by("id desc").all()
    num_of_items = ("%s %s" % (len(items), ' items' if len(items) > 1 else ' item'))
    return render_template('showCategories.html', categories = categories, items = items, isLoggedIn = isLoggedIn(login_session), category_name = category_name, num_of_items = num_of_items)

@app.route('/categories/<string:category_name>/<string:item_name>')
def showItems(category_name, item_name):
    session = DBSession()    
    item = session.query(Item).filter_by(category_name = category_name, name = item_name).one()
    c_user_id = item.user_id
    hideEdit = True if not isLoggedIn(login_session) or c_user_id != login_session['user_id'] else False
    return render_template('showItem.html', item = item, hideEdit = hideEdit, isLoggedIn = isLoggedIn(login_session))

def isLoggedIn(login_session):
    if 'user_id' not in login_session or login_session['user_id'] is None:
        return False
    else:
        return True
    
@app.route('/categories/items/add', methods = ['POST', 'GET'])
def addItem():
    session = DBSession()
    if isLoggedIn(login_session) is False:
        return redirect(url_for('showLogin'))
    else:
        if request.method == 'GET':
            categories = session.query(Category).all()
            return render_template('add.html', categories = categories, isLoggedIn = isLoggedIn(login_session))
        if request.method == 'POST':
            item_name = request.form.get('item_name')
            item_description = request.form.get('item_description')
            item_category = request.form.get('item_category')
            user_id = login_session['user_id']
            item = Item(name = item_name, description = item_description, category_name = item_category, user_id = user_id)
            session.add(item)
            session.commit()
            c_user_id = item.user_id
            hideEdit = True if not isLoggedIn(login_session) or c_user_id != login_session['user_id'] else False
            return render_template('showItem.html', item = item, hideEdit = hideEdit, isLoggedIn = isLoggedIn(login_session))
    

@app.route('/categories/<string:category_name>/<string:item_name>/edit', methods = ['POST', 'GET'])
def editItem(category_name, item_name):
    session = DBSession()
    if isLoggedIn(login_session) is False:
        return redirect(url_for('showLogin'))
    else:
        if request.method == 'GET':
            categories = session.query(Category).all()
            item = session.query(Item).filter_by(category_name = category_name, name = item_name).one()
            if item.user_id != login_session['user_id']:
                return 'Access denied.'
            return render_template('edit.html', categories = categories, isLoggedIn = isLoggedIn(login_session), item = item)
        if request.method == 'POST':
            item = session.query(Item).filter_by(category_name = category_name, name = item_name).one()
            if item.user_id != login_session['user_id']:
                return 'Access denied.'
            new_item_name = request.form.get('item_name')
            new_item_description = request.form.get('item_description')
            new_item_category = request.form.get('item_category')
            item.category_name = new_item_category
            item.name = new_item_name
            item.description = new_item_description
            session.commit()
            c_user_id = item.user_id
            hideEdit = True if not isLoggedIn(login_session) or c_user_id != login_session['user_id'] else False
            return render_template('showItem.html', item = item, hideEdit = hideEdit, isLoggedIn = isLoggedIn(login_session))
    
@app.route('/categories/<string:category_name>/<string:item_name>/delete', methods = ['GET', 'POST'])
def deleteItem(category_name, item_name):
    session = DBSession()
    if isLoggedIn(login_session) is False:
        return redirect(url_for('showLogin'))
    else:
        if request.method == 'GET':
            item = session.query(Item).filter_by(category_name = category_name, name = item_name).one()
            if item.user_id != login_session['user_id']:
                return 'Access denied.'
            return render_template('delete.html', isLoggedIn = isLoggedIn(login_session), item = item)
        if request.method == 'POST':
            item = session.query(Item).filter_by(category_name = category_name, name = item_name).one()
            if item.user_id != login_session['user_id']:
                return 'Access denied.'
            session.delete(item)
            session.commit()
            categories = session.query(Category).all()
            items = session.query(Item).order_by("id desc").all()
            return render_template('showLatest.html', categories = categories, items = items, isLoggedIn = isLoggedIn(login_session))
    
@app.route('/login')
def showLogin():
    session = DBSession()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', state = state, hideLogin = True)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    print 'statesToken: ' + request.args.get('state')
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if user_id is None:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output
    
@app.route('/gconnect', methods=['POST'])
def gconnect():
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session['access_token']
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
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
    
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'DELETE')[1])
    if 'success' in result and result['success'] == True:
        del login_session['access_token']
        del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        del login_session['user_id']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
#        return response
        return redirect(url_for('showLatest'))
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response 

@app.route('/gdisconnect')
def disconnect():
    session = DBSession()
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        del login_session['user_id']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
#        return response
        return redirect(url_for('showLatest'))
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/logout')
def logout():
    if login_session['provider'] == 'google':
        return disconnect()
    elif login_session['provider'] == 'facebook':
        return fbdisconnect()
    
def getUserID(email):
    session = DBSession()
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None

def getUserInfo(user_id):
    session = DBSession()
    user = session.query(User).filter_by(id = user_id)
    return user
    
def createUser(login_session):
    session = DBSession()
    newUser = User(username = login_session['username'], email = login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id
    
if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    #app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host= '0.0.0.0', port= 5000)    