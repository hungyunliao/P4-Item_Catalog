from models import Base, User, Category, Item
from flask import Flask, jsonify, request, url_for, \
    abort, g, render_template, redirect, flash
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

user = User(username='testuser')
user.hash_password('testps')
session.add(user)

cate = Category(name='Soccer')
session.add(cate)

cate = Category(name='Basketball')
session.add(cate)

cate = Category(name='Baseball')
session.add(cate)

cate = Category(name='Frisbee')
session.add(cate)

cate = Category(name='Snowboarding')
session.add(cate)

cate = Category(name='Rock Climbing')
session.add(cate)

cate = Category(name='Foosball')
session.add(cate)

cate = Category(name='Skating')
session.add(cate)

cate = Category(name='Hockey')
session.add(cate)

item = Item(
    name='T-shirt', description='A soccer T-shit that gives you energy.',
    category_name='Soccer', user_id=user.id
)
session.add(item)

item = Item(
    name='Sneakers', description='A pair of shoes, dirty.',
    category_name='Basketball', user_id=user.id
)
session.add(item)

item = Item(
    name='Bat', description='A wooden stick for hitting balls.',
    category_name='Baseball', user_id=user.id
)
session.add(item)

item = Item(
    name='Helmet', description='A metal hat.',
    category_name='Baseball', user_id=user.id
)
session.add(item)

session.commit()
