"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required

# Creat flask app
api = Blueprint('api', __name__)

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@api.route("/TOKEN", methods=["POST"])
def create_token():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    if email == "" or password == "":
        return jsonify({"msg": "Bad username or password"}), 401
    
    user = User.query.filter_by(email = email).first()
    if not user: 
        return jsonify ({"msg": "User not found!"})

    if user.password != password: 
        return jsonify ({"msg": "Password incorrect."})

    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token)

# signup a new user
@api.route("/signup", methods=["POST"])
def create_user():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    if email == "" or password == "":
        return jsonify({"msg": "Field missing"}), 401
    
    # check = User.query.filter_by(email = email).first()
    # if not check:
    #     return jsonify({"msg": "Email already in use."})
    
    user = User(email = email, password = password, is_active = True)

    db.session.add(user)

    db.session.commit()    
    
    return jsonify(user.serialize())
