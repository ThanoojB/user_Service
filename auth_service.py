from flask import Blueprint, request, jsonify
from pymongo import MongoClient
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import config
from bson.objectid import ObjectId
from functools import wraps

client = MongoClient(config.MONGO_URI)
db = client['usersdb']
users = db['users']

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')

    if not username or not email or not password or not confirm_password:
        return jsonify({"error": "All fields are required"}), 400
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400
    if users.find_one({"email": email}):
        return jsonify({"error": "Email already exists"}), 400
    
    hashed_password = generate_password_hash(password)

    users.insert_one({ 
        "username":username,
        "email":email,
        "password":hashed_password,
        "role": "user",
        "created_at": datetime.datetime.utcnow()
    })

    return jsonify({"message": "User created successfully", "user": {"username": username, "email": email, "role": "user"}}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        identifier = data.get('identifier')
        password = data.get('password')

        if not identifier or not password:
            return jsonify({"error": "Email and password are required"}), 400

        user = users.find_one({"$or": [{"email": identifier}, {"username": identifier}]})

        if not user or not check_password_hash(user['password'], password):
            return jsonify({"error": "Invalid password"}), 401

        access_token = create_access_token(identity=
                                           {"username": user['username'], "email": user['email'], "role": user.get('role', 'user')},
                                               expires_delta=datetime.timedelta(hours=1))
        return jsonify({
            "message": "Login successful",
            "token": access_token,
            "user": {
                "username": user['username'],
                "email": user['email'],
                "role": user.get('role', 'user')
            }
        }), 200

    except Exception as e:
        print("Login Exception:", str(e))
        return jsonify({"error": "An unexpected error occurred"}), 500
