from models import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for, abort, g, render_template, redirect, flash
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

# from flask.ext.httpauth import HTTPBasicAuth (flask.ext.httpauth is deprecated,)
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind = engine)
session = DBSession()
app = Flask(__name__)

#cate = Category(name = 'Soccer')
#session.add(cate)
#session.commit()

@app.route('/')
@app.route('/categories')
def showLatest():
    session = DBSession()
    categories = session.query(Category).all()
#    return jsonify(categories = [c.name for c in categories])
    return render_template('index.html', categories = categories)
    

    
if __name__ == '__main__':
    app.debug = True
    #app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    app.run(host= '0.0.0.0', port= 5000)    