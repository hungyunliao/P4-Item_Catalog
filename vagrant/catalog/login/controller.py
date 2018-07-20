from flask import (jsonify,
                   request,
                   abort,
                   g)
from flask import Blueprint
from models import Base, User, Category, Item
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, exc
from flask_httpauth import HTTPBasicAuth

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
auth = HTTPBasicAuth()

login = Blueprint('login', __name__)


# ADD @auth.verify_password decorator here
@auth.verify_password
def verify_passowrd(username_or_token, password):
    session = DBSession()
    # use token to verify first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        # if token is provided and passed
        user = session.query(User).filter_by(id=user_id).one_or_none()
    else:
        # if not passed, use username:password verification instead
        user = session.query(User) \
            .filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@login.route('/tokens', methods=['POST'])
@auth.login_required
def getToken():
    """ Return a 10 mins lifespan token for a user to access
    JSON endpoints
    """

    session = DBSession()
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@login.route('/users', methods=['POST'])
def createUser():
    """ Create a user with a password that is allowed to
    access JSON endpoints.
    """

    session = DBSession()
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)
    user = session.query(User) \
        .filter_by(username=username).first()
    if user is not None:
        abort(400)
    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({'username': user.username}), 201


@login.route('/categories.json')
@auth.login_required
def showJSON():
    """ Return a JSON file including all the
    info (categories, items) displayed on the website.
    """

    session = DBSession()
    categories = session.query(Category).all()
    data = []
    for cate in categories:
        items = session.query(Item) \
            .filter_by(category_name=cate.name).all()
        jsonfile = {
            'id': cate.id,
            'name': cate.name,
            'item': [i.serialize for i in items]
        }
        data.append(jsonfile)
    return jsonify(Category=data)