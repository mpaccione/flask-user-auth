from flask import Flask, redirect, request, jsonify, render_template, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
import base64
import os
import dotenv
import json
import requests

dotenv.load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'postgresql://postgres:postgres@db:5432/upwork_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'supersecretkey')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User model


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# Routes
headers = {
    "Content-Type": "application/json",
    'x-stack-access-type': 'server',
    'x-stack-project-id': os.getenv("NEXT_PUBLIC_STACK_PROJECT_ID"),
    'x-stack-secret-server-key':  os.getenv("STACK_SECRET_SERVER_KEY")
    # 'x-stack-access-token': os.getenv("NEXT_PUBLIC_STACK_PUBLISHABLE_CLIENT_KEY"),
}

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

#
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing fields'}), 400

    # NOTE: This code below is for generating a password hash and User Object to be stored in the db. However with StackAuth this is a SaaS,

    # hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    # new_user = User(username=username, email=email, password=hashed_password)

    # try:
    #     db.session.add(new_user)
    #     db.session.commit()
    #     return jsonify({'message': 'User created successfully'}), 201

    try:
        url = "https://api.stack-auth.com/api/v1/auth/password/sign-up"
        payload = {
            "email": email,
            "password": password,
            "verification_callback_url": "http://localhost:5000/email-verification"
        }

        res = requests.post(url, json=payload, headers=headers)

        if res.status_code == 200:
            response = make_response(
                redirect('http://localhost:5000/dashboard'))

            cookie_value = base64.b64encode(
                json.dumps(res.json()).encode("utf-8")
            ).decode("utf-8")

            response.set_cookie(
                'access_cookie', cookie_value, max_age=60*60*24)

            return response

        return jsonify(res.json())
    except Exception as e:
        return jsonify({'error': 'User creation failed', 'message': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # NOTE: This code gets users data out of the database by email, decrypts the password and verifies match

    # user = User.query.filter_by(email=email).first()

    # if user and bcrypt.check_password_hash(user.password, password):
    #     access_token = create_access_token(
    #         identity={'id': user.id, 'username': user.username})

    if email and password:

        url = "https://api.stack-auth.com/api/v1/auth/password/sign-in"

        payload = {
            "email": email,
            "password": password
        }
        res = requests.post(url, json=payload, headers=headers)

        if res.status_code == 200:
            response = make_response(
                redirect('http://localhost:5000/dashboard'))

            cookie_value = base64.b64encode(
                json.dumps(res.json()).encode("utf-8")
            ).decode("utf-8")

            response.set_cookie(
                'access_cookie', cookie_value, max_age=60*60*24)

            return response
    else:
        return jsonify({'error': 'Invalid credentials'}), 401


# @app.route('/user/<int:user_id>', methods=['GET'])
# def get_user(user_id):
#     user = User.query.get(user_id)

#     if user:
#         return jsonify({'id': user.id, 'username': user.username, 'email': user.email}), 200
#     else:
#         return jsonify({'error': 'User not found'}), 404


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
