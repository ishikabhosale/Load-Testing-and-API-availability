import os
import secrets
from app import app, db, login_manager
from app import bcrypt
from PIL import Image
from flask import Flask, render_template, url_for, flash, redirect, request, jsonify, abort
import requests
import json
import uuid
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, \
    jwt_refresh_token_required, create_refresh_token, get_raw_jwt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from flask_mail import Mail
from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User, LoginForm, AddUser, Test, Token

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# This reads header api token keys 
@login_manager.request_loader
def load_user_from_request(request):
    api_key = request.headers.get('Authorization')
    if api_key:
        api_key = api_key.replace('Token ', '', 1)
        token = Token.query.filter_by(uuid=api_key).first()
        if token:
            return token.user
    return None

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

#Creating User & Post table to store data



# All routing will goes here
@app.route('/')
def home():
    """
    url = "http://128.199.22.204/v1/tests/"
    payload={}
    headers = {}
    all_users = User.query.all()[0]
    response = requests.request("GET", url, headers=headers, data=payload).json()
    for test in response: 
        p_id = test["id"]
        d_t = test["updated_at"]
        t = Test(predator_id = p_id, date_posted = d_t, author = all_users)
        db.session.add(t)
        db.session.commit()
    return "yessss"
    """

password1 = '123456'

@app.after_request
def apply_caching(response):
    response.headers["Access-Control-Allow-Headers"] = "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    return response

@app.route('/api/signin', methods=['POST', 'OPTIONS', 'GET'])
def signin():
    print(request.method)
    if request.method == 'GET': 
        if current_user.is_authenticated: 
            next = request.args.get('next')
            if next: 
                return redirect(next)
        return "", 200
    if request.method == 'POST':
        print(request.data)
        data = request.get_json()
        user = User.query.filter_by(email=data["email"]).first()
        if not user:
            return jsonify({
                "success" : False, 
                "message" : "No user"
            })
        hashed_password = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        if bcrypt.check_password_hash(hashed_password, password1):
            token = Token.query.filter_by(user_id=user.id).first()
            if not token:
                token = Token(user_id=user.id, uuid=str(uuid.uuid4().hex))
                db.session.add(token)
                db.session.commit()
            print(token)
            login_user(user)
            next = request.args.get('next')
            if next: 
                return redirect(next)
            return jsonify({
                    "success":True,
                    "user":{
                            'user_id': current_user.id,
                            "name":user.username },
                    "token": token.uuid
                }) 
        else:
            return jsonify({
                            "success":False,
                    "message":"Check Password or user details"
                })
    else:
        return "",200



@app.route('/api/getCurrentUser', methods=['GET', 'OPTIONS'])
@login_required
def getCurrentUser():
    if request.method == 'GET': 
        return jsonify({
            'success': True,
            'user':{
                'user_id': current_user.id,
            'name' :current_user.username, 
            'email' : current_user.email
            }
        })
    else: 
        return "", 200


@app.route('/signout')
@login_required
def logout():
    token = Token.query.filter_by(user_id=current_user.id).first()
    if token:
        db.session.delete(token)
        db.session.commit()
    logout_user()
    flash("You have logged out")
    return jsonify({
        'success':True,
    })
   


def getFirstReport(p_id):
    url = "http://128.199.22.204/v1/tests/" + p_id + "/reports"
    payload={}
    headers = {}

    response = requests.request("GET", url, headers=headers, data=payload)
    if response!= []: 
        return response.json()
    return []



@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    i = current_user.id
    test1 = Test.query.filter_by(user_id = i).all()
    print(test1)
    jsonised_object_list = []
    for i in test1:
        result = getFirstReport(i.predator_id)
        new_test = i.as_dict()
        if result!= []:
            new_test['last_success_rate'] = result[0]["last_success_rate"]
            new_test['report_id'] = result[0]["report_id"]
        else:
            new_test['last_success_rate'] = "No job yet"
            new_test['report_id'] = '#'
        jsonised_object_list.append(new_test)
    print(test1)
    print("YeSSSS")
    return jsonify({
            'success': True,
            'tests': jsonised_object_list
            }) 

@app.route('/tests/<test_id>', methods = ['GET'])
@login_required
def testjob(test_id):
    test = Test.query.filter_by(predator_id = test_id).first()
    if test.user_id == current_user.id or 4:
        url = "http://128.199.22.204/v1/tests" + "/" + test_id + "/reports"
        payload={}
        headers = {}
        response = requests.request("GET", url, headers=headers, data=payload)
        print(response.text)
        return jsonify({
            'success':True, 
            'reports': response.json()
        })
    return jsonify({
            'success':False 
        })

@app.route('/tests/<test_id>/<report_id>', methods = ['GET'])
@login_required
def testreport(test_id, report_id):
    test = Test.query.filter_by(predator_id = test_id).first()
    if test.user_id == current_user.id: 
        url = "http://128.199.22.204/v1/tests" + "/" + test_id + "/reports/" + report_id
        payload={}
        headers = {}
        response = requests.request("GET", url, headers=headers, data=payload)
        print(response.text)
        return jsonify({
            'success':True, 
            'report': response.json()
        })
    return jsonify({
            'success':False 
        })


@app.route('/admin', methods=['GET', 'POST', 'OPTIONS'])
@login_required
def admin():
    if request.method == 'GET': 
        if current_user.email == "admin@gmail.com":
            all_users = User.query.all()
            jsonised_object_list_users = []
            for user in all_users:
                jsonised_object_list_users.append(user.as_dict())
            print(jsonised_object_list_users)
            url = "http://128.199.22.204/v1/tests"
            payload={}
            headers = {
                'Content-Type': 'application/json'
            }
            response = requests.request("GET", url, headers=headers, data=payload).json()
            for i in response:
                result = getFirstReport(i["id"])
                if result!= []:
                    """
                    i.add("last_success_rate" , result[0]["last_success_rate"])
                    i.add("report_id", result[0]["report_id"] ) """
                    i["last_success_rate"] = result[0]["last_success_rate"]
                    i["report_id"] = result[0]["report_id"]

                    """
                    i.append(jsonify({
                        "last_success_rate" : result[0]["last_success_rate"], 
                        "report_id" : result[0]["report_id"]
                    }))
                    """
                else:
                    i["last_success_rate"] = "No job yet"
                    i["report_id"] = '#'
                    """
                    i.add("last_success_rate" , "No job yet")
                    i.add("report_id",'#')"""
                    """
                     i.append(jsonify({
                        "last_success_rate" : "No job yet", 
                        "report_id" : '#'
                    })) """

                    print(i)
            return jsonify(
                {
                    "success" : True, 
                    "all_users" : jsonised_object_list_users,
                    "all_tests" : response 
                }
            )
    if request.method == 'POST': 
        if current_user.email == "admin@gmail.com": 
            data = request.get_json()
            check_email = User.query.filter_by(email=data['email']).first() 
            if check_email:  
                return jsonify({
                    "success":False,
                    "message":"Email taken"})
            new_user = User(username=data['name'],  
                        email=data['email'],
                        )
            db.session.add(new_user)
            db.session.commit()
            flash(f'Your user has been created!', 'success')
            # return redirect(url_for('admin'))
            return jsonify({
                    "success":True}) 
    return "", 200

@app.route('/createtest/', methods = ['POST'])
#@login_required
def createtest():
    t = request.get_json(force = True)
    url = "http://128.199.22.204/v1/tests"
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, json = t)
    """
    predator_id1 = response.json()
    test = Test(predator_id = predator_id1["id"], author = current_user)
    db.session.add(test)
    db.session.commit()
    flash(f'Your test has been created!', 'success')
    print("id is ", predator_id1["id"])
    """
    print(response.text)

    return response.text



@app.route('/createjob/<string:test_id>/', methods = ["GET", "POST"])
def createjob(test_id): 
    test = Test.query.filter_by(predator_id = test_id).first()
    i = test.predator_id
    t = request.get_json(force = True)
    t["test_id"] = i 
    url = "http://128.199.22.204/v1/jobs"
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, json = t)
    print(response.text)

    return response.text



