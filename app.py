import os, hashlib, binascii
from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy import exc
from flask_migrate import Migrate

app = Flask(__name__)

db_path = os.path.join(os.path.dirname(__file__), 'test.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./test.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    salt = db.Column(db.String(16), nullable= False)

    def __repr__(self):
        return '<User,{}>'.format(self.username)

db.create_all()


@app.route('/users/', methods=["GET", "POST", "DELETE"])
def users():
    if request.method == "POST":
        data = request.json
        if not all((data.get("username"), data.get("email"), data.get("password"))):
            return jsonify({"error": {"description" : "All fields are mandatory"}}), 400
        salt = os.urandom(16)
        psw = hashlib.pbkdf2_hmac('sha512', data.get("password").encode(), salt, 10000)
        u = User(username=data.get("username"), email=data.get("email"), password=binascii.hexlify(psw), salt=salt)
        db.session.add(u)
        try:
            db.session.commit()
        except IntegrityError as e:
            print(e)
            return jsonify({"error": {"description":"User already exist"}}), 400
        else:
            return jsonify({"data":{"username": u.username, "email": u.email}}), 201
    elif request.method == "GET":
        users = User.query.all()
        result = [{"username": u.username, "email": u.email, "password": str(u.password)} for u in users]
        return jsonify({"data":result}), 200
    elif request.method == "DELETE":
        data = request.json
        username = data.get("username")
        usr = User.query.filter_by(username=username).first()
        if usr:
            db.session.delete(usr)
            try:
                db.session.commit()
                return jsonify({"error":{"description": "User deleted"}}), 200
            except exc.SQLAlchemyError as e:
                print(e)
                return jsonify({"error":{"description": "Error while processing request"}}), 400
        else:
            return jsonify({"error":{"description": "User does not exist"}}), 400


@app.route('/users/<username>', methods=["PUT"])
def update_user(username):
    data = request.json
    email = data.get("email")
    password = data.get("password")
    usr = User.query.filter_by(username=username).first()
    if usr:
        if email:
            usr.email = email
        if password:
            usr.password = password
        try:
            db.session.commit()
            return jsonify({"data":{"description": "User updated"}}), 200
        except exc.SQLAlchemyError as e:
            print(e)
            return jsonify({"error":{"description": "Error while processing request"}}), 400
    else:
        return jsonify({"error":{"description": "User does not exist"}}), 400


@app.route('/users/auth/', methods=["POST"])
def users_auth():
    if request.method == "POST":
        data = request.json
        email = data.get("email")
        password = data.get("password")
        if not all((email, password)):
            return jsonify({"error": {"description": "Email and password are required"}}), 400
        usr = User.query.filter_by(email=email).first()
        if usr:
            hash_psw = binascii.hexlify(hashlib.pbkdf2_hmac('sha512', password.encode(), usr.salt, 10000))
            if usr.password == hash_psw:
                return jsonify({"data": {"username": usr.username, "email": usr.email}}), 200
            else:
                return jsonify({"error":{"description": "Email or password are wrong"}}), 404
        else:
            return jsonify({"error":{"description": "Email or password are wrong"}}), 404

if __name__ == "main":
    app.run()
