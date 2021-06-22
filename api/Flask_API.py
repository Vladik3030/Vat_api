from functools import wraps

import datetime
import jmespath
import requests
from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

app = Flask(__name__)
app.config["DEBUG"] = True
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_key = db.Column(db.String(80), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Bearer' in request.headers:
            token = request.headers['Bearer']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_key=data['public_key']).first()
        except:
            return jsonify({'message': 'Token is missing'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


supported_countries = {"Great Britain": {
    "countryCode": "GB"}}

example_of_VATs = {'valid': ['264770679', '340268127'],
                   'notValid': ['740268127', 'fsfsfsfsfsf']}


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({"message": "You don't have a permission to that func"})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {'public_key': user.public_key, 'name': user.name,
                     'password': user.password, 'admin': user.admin}
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/user/<public_key>', methods=['GET'])
@token_required
def get_one_user(current_user, public_key):
    if not current_user.admin:
        return jsonify({"message": "You don't have a permission to that func"})

    user = User.query.filter_by(public_key=public_key).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {'public_key': user.public_key, 'name': user.name,
                 'password': user.password, 'admin': user.admin}

    return jsonify({'user': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({"message": "You don't have a permission to that func"})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_key=str(uuid.uuid4()), name=data['name'],
                    password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created'})


@app.route('/user/<public_key>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_key):
    if not current_user.admin:
        return jsonify({"message": "You don't have a permission to that func"})

    user = User.query.filter_by(public_key=public_key).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted'})


@app.route('/user/<public_key>', methods=['PUT'])
@token_required
def promote_user(current_user, public_key):
    if not current_user.admin:
        return jsonify({"message": "You don't have a permission to that func"})

    user = User.query.filter_by(public_key=public_key).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401,
                             {'WWW-Authenticate': 'Basic realm="Login required!'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401,
                             {'WWW-Authenticate': 'Basic realm="Login required!'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_key': user.public_key,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                           app.config['SECRET_KEY'])

        return jsonify({'token': token.decode("UTF-8")})

    return make_response('Could not verify', 401,
                         {'WWW-Authenticate': 'Basic realm="Login required!'})


@app.route('/supported_countries/cases', methods=['GET'])
def show_cases():
    return supported_countries


@app.route('/examples', methods=['GET'])
def show_vats():
    return jsonify(example_of_VATs)


# A route to return all of the available entries in our catalog.
@app.route('/fiscal-number-information/<string:country>/<string:vat>', methods=['GET'])
@token_required
def validate(current_user, vat, country):
    if not current_user.admin:
        return jsonify({"message": "You don't have a permission to that func"})

    api_response = requests.get(
        'https://api.service.hmrc.gov.uk/organisations/vat/check-vat-number/lookup/{0}'.format(vat)).json()

    def foreach_sum(response):
        list_location = jmespath.search('target.address.*', response)
        value = ""
        for i in list_location:
            value += i + " "
        return value

    def creating_json():
        new_json = {}
        if jmespath.search('target.vatNumber', api_response) == vat and jmespath.search('target.address.countryCode',
                                                                                        api_response) == country:
            new_json.update({'valid': "True" if jmespath.search('target.vatNumber',
                                                                api_response) == vat else "False",
                             'businessName': jmespath.search('target.name', api_response),
                             'businessAddress': foreach_sum(api_response)})
        else:
            new_json.update({'valid': 'False',
                             'errorMessage': 'Enter the UK VAT number you want to check in the correct format'})

        return new_json

    return jsonify((creating_json()))
