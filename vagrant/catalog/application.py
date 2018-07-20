from functools import wraps
from models import Base, User, Category, Item
from flask import (Flask,
                   request,
                   url_for,
                   abort,
                   g,
                   render_template,
                   redirect)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, exc
from flask import session as login_session

import json

from login.controller import login
from oauth.controller import oauth

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

app.register_blueprint(login, url_prefix='/')
app.register_blueprint(oauth, url_prefix='/')

FB_APP_ID = json.loads(
        open('fb_client_secrets.json', 'r').read()
    )['web']['app_id']
FB_APP_SECRET = json.loads(
        open('fb_client_secrets.json', 'r').read()
    )['web']['app_secret']


def isLoggedIn(login_session):
    if ('user_id' not in login_session or
            login_session['user_id'] is None):
        return False
    else:
        return True


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if isLoggedIn(login_session) is False:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@app.route('/categories')
def showLatest():
    """ Show items in ALL categories """

    session = DBSession()
    categories = session.query(Category).all()
    # list the latest itmes chronologically
    items = session.query(Item).order_by("id desc").all()
    return render_template(
        'showLatest.html',
        categories=categories,
        items=items,
        isLoggedIn=isLoggedIn(login_session)
    )


@app.route('/categories/<string:category_name>')
@app.route('/categories/<string:category_name>/items')
def showCategoryItems(category_name):
    """ Show items in a CERTAIN categories """

    session = DBSession()
    categories = session.query(Category).all()
    items = session.query(Item) \
        .filter_by(category_name=category_name).order_by("id desc").all()
    num_of_items = (
        "%s %s" %
        (len(items), ' items' if len(items) > 1 else ' item')
    )
    return render_template(
        'showCategories.html',
        categories=categories,
        items=items,
        isLoggedIn=isLoggedIn(login_session),
        category_name=category_name,
        num_of_items=num_of_items
    )


@app.route('/categories/<string:category_name>/<string:item_name>')
def showItems(category_name, item_name):
    """ Show the item details.
    Hide the Edit | Delete button if the user is not logged in or
    the user does not own the item.
    """

    session = DBSession()
    item = session.query(Item) \
        .filter_by(category_name=category_name, name=item_name).one_or_none()
    c_user_id = item.user_id
    hideEdit = True if not isLoggedIn(login_session) or \
        c_user_id != login_session['user_id'] else False
    return render_template(
        'showItem.html',
        item=item,
        hideEdit=hideEdit,
        isLoggedIn=isLoggedIn(login_session)
    )


@app.route('/categories/items/add', methods=['POST', 'GET'])
@login_required
def addItem():
    """ Add an item """

    session = DBSession()
    if request.method == 'GET':
        categories = session.query(Category).all()
        return render_template(
            'add.html',
            categories=categories,
            isLoggedIn=isLoggedIn(login_session)
        )
    elif request.method == 'POST':
        item_name = request.form.get('item_name')
        item_description = request.form.get('item_description')
        item_category = request.form.get('item_category')
        user_id = login_session['user_id']
        item = Item(
            name=item_name,
            description=item_description,
            category_name=item_category,
            user_id=user_id
        )
        session.add(item)
        session.commit()
        return redirect(
            url_for(
                'showItems',
                category_name=item.category_name,
                item_name=item.name
            )
        )


@app.route('/categories/<string:category_name>/<string:item_name>/edit',
           methods=['POST', 'GET'])
@login_required
def editItem(category_name, item_name):
    """ Edit an item.
    An item can only be edited by the user who owns it.
    """

    session = DBSession()
    if request.method == 'GET':
        categories = session.query(Category).all()
        item = session.query(Item).filter_by(
            category_name=category_name,
            name=item_name
        ).one_or_none()

        # if the user does not own it, return.
        if item.user_id != login_session['user_id']:
            return 'Access denied.'
        return render_template(
            'edit.html',
            categories=categories,
            isLoggedIn=isLoggedIn(login_session),
            item=item
        )
    elif request.method == 'POST':
        item = session.query(Item).filter_by(
            category_name=category_name,
            name=item_name
        ).one_or_none()

        # if the user does not own it, return.
        if item.user_id != login_session['user_id']:
            return 'Access denied.'
        new_item_name = request.form.get('item_name')
        new_item_description = request.form.get('item_description')
        new_item_category = request.form.get('item_category')
        item.category_name = new_item_category
        item.name = new_item_name
        item.description = new_item_description
        session.commit()
        return redirect(
            url_for(
                'showItems',
                category_name=item.category_name,
                item_name=item.name
            )
        )


@app.route('/categories/<string:category_name>/<string:item_name>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(category_name, item_name):
    """ Delete an item.
    An item can only be deleted by the user who owns it.
    """

    session = DBSession()
    if request.method == 'GET':
        item = session.query(Item).filter_by(
            category_name=category_name,
            name=item_name
        ).one_or_none()

        # if the user does not own it, return.
        if item.user_id != login_session['user_id']:
            return 'Access denied.'
        return render_template(
            'delete.html',
            isLoggedIn=isLoggedIn(login_session),
            item=item)
    if request.method == 'POST':
        item = session.query(Item).filter_by(
            category_name=category_name,
            name=item_name
        ).one_or_none()

        # if the user does not own it, return.
        if item.user_id != login_session['user_id']:
            return 'Access denied.'
        session.delete(item)
        session.commit()
        categories = session.query(Category).all()
        items = session.query(Item).order_by("id desc").all()
        return redirect(url_for('showLatest'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
